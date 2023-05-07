use actix_web::{
    get, web, App, HttpServer, Responder, HttpResponse,
    HttpRequest, cookie::Cookie, cookie::time::Duration as CDuration,
    http::header
};
use oauth2::{basic::BasicClient, TokenResponse};
// Alternatively, this can be oauth2::curl::http_client or a custom.
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, Scope, TokenUrl,
};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH, SystemTime};
use uuid::Uuid;
use actix_web::middleware::Logger;
use env_logger::Env;
use tokio::time::interval;
use std::env;
use jsonwebtoken::{decode, DecodingKey, Validation};
use log::{debug, error, info, trace, warn};

#[derive(Serialize, Debug)]
struct LoginResponse {
    session_id: String,
}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    error: &'static str,
}

#[derive(Deserialize, Debug)]
struct CodeResponse {
    code: String,
    state: String
}

#[derive(Debug)]
struct AuthorizationSession {
    client: BasicClient,
    timeout: Instant,
    source_uri: String,
    pkce_code_verifier: oauth2::PkceCodeVerifier,
    csrf_state: CsrfToken,
}

type AuthStore = Arc<Mutex<HashMap<String, AuthorizationSession>>>;

#[derive(Clone)]
struct AppData {
    session_auth_store: AuthStore,
    google_client_id: ClientId,
    google_client_secret: ClientSecret,
    authentication_success_url: String,
    google_keys: Vec<DecodingKey>,
    jwt_secret: ClientSecret,
}

#[derive(Deserialize, Debug)]
struct GoogleToken {
    iss: String,
    sub: String,
    // aud: String,
    // azp: String,
    // iat: usize,
    // exp: usize,
    email: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthToken{
    sub: String,
    exp: u64,
    email: String,
}

fn get_header_string(req: &HttpRequest, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let ret = req.headers()
        .get(key)
        .ok_or(format!("Header {} not found", key))?
        .to_str()?;
    Ok(ret.to_string())
}

fn validate_google_token(app_data: &AppData, token: &str) -> Result<GoogleToken, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[&app_data.google_client_id.as_str()]);
    validation.set_issuer(&["accounts.google.com", "https://accounts.google.com"]);

    debug!("Trying validate token: token {}, audience {}", token, app_data.google_client_id.as_str());

    for key in &app_data.google_keys {
        match decode::<GoogleToken>(token, key, &validation) {
            Ok(decoded_token) => {
                return Ok(decoded_token.claims);
            },
            Err(err) => {
                debug!("decode token failed: {} ({:?})", err, err.kind());
            }
        }
    }
    
    let mut validation_fake = Validation::new(jsonwebtoken::Algorithm::RS256);
    // validation_fake.set_audience(&[&app_data.google_client_id.as_str()]);
    // validation_fake.set_issuer(&["accounts.google.com", "https://accounts.google.com"]);
    validation_fake.insecure_disable_signature_validation();
    match decode::<GoogleToken>(token, &app_data.google_keys[0], &validation_fake) {
        Ok(decoded_token) => {
            debug!("decoded token header {:?}, claims {:?}", decoded_token.header, decoded_token.claims);
        },
        Err(err) => {
            debug!("decode token failed: {} ({:?})", err, err.kind());
        }
    }

    Err(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken))
}

fn finish_login(app_data: &AppData, source_uri: String, token: GoogleToken) -> HttpResponse {
    let expiration_seconds = 3600;
    let exp = SystemTime::now().duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() + expiration_seconds;

    let claims = AuthToken {
        sub: token.sub.clone(),
        email: token.email.clone(),
        exp,
    };

    let secret = jsonwebtoken::EncodingKey::from_secret(app_data.jwt_secret.secret().as_bytes());

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let auth_token = jsonwebtoken::encode(&header, &claims, &secret).unwrap();

    HttpResponse::Found()
        .cookie(
            Cookie::build("session_id", auth_token)
                .path("/")
                .secure(true)
                .max_age(CDuration::seconds(expiration_seconds.try_into().unwrap()))
                .finish(),
        )
        .append_header((header::LOCATION, source_uri))
        .finish()
}

#[get("/auth/login")]
async fn login(
    req: HttpRequest,
    web::Query(data): web::Query<CodeResponse>,
    app_data: web::Data<AppData>,
) -> impl Responder {
    let session_id = match get_header_string(&req, "X-Session-Id") {
        Ok(value) => value,
        Err(err) => {
            info!("failed to get X-Session-Id from headers: {}", err);
            return HttpResponse::Unauthorized().json(ErrorResponse { error: "No session ID" })
        },
    };
    let code = AuthorizationCode::new(data.code);
    let state = CsrfToken::new(data.state);

    let mut auth_store = app_data.session_auth_store.lock().unwrap();

    if let Some(auth_data) = auth_store.remove(&session_id) {
        if auth_data.timeout > Instant::now() {
            if state.secret() != auth_data.csrf_state.secret() {
                return HttpResponse::Unauthorized().json(ErrorResponse { error: "State mismatch" });
            }
            let token_response = auth_data.client
                .exchange_code(code)
                .set_pkce_verifier(auth_data.pkce_code_verifier)
                .request_async(async_http_client)
                .await;

            match token_response {
                Ok(token_response_unwrapped) => {
                    match validate_google_token(&app_data, token_response_unwrapped.access_token().secret()) {
                        Ok(token) => finish_login(&app_data, auth_data.source_uri, token),
                        Err(err) => {
                            info!("google token validation failed {}", err);
                            HttpResponse::InternalServerError()
                                .json(ErrorResponse { error: "No email found in the JWT" })
                        },
                    }
                },
                Err(err) => {
                    info!("google token fetch failed {}", err);
                    HttpResponse::Unauthorized()
                        .json(ErrorResponse { error: "failed to prove token" })
                },
            }
        } else {
            HttpResponse::Unauthorized().json(ErrorResponse { error: "Session expired" })
        }
    } else {
        HttpResponse::Unauthorized().json(ErrorResponse { error: "No session found" })
    }
}

async fn renew_session(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> HttpResponse {

    let source_method = get_header_string(&req, "X-Original-Method").unwrap_or("GET".to_string());
    let source_uri = if source_method == "GET" {
        get_header_string(&req, "X-Original-URI").unwrap_or(app_data.authentication_success_url.clone())
    } else {app_data.authentication_success_url.clone()};
    let redirect_uri = match get_header_string(&req, "X-Redirect-URI") {
        Ok(value) => match RedirectUrl::new(value) {
            Ok(value) => value,
            Err(err) => return HttpResponse::InternalServerError()
                .body(format!("X-Redirect-URI parse error: {}", err))
        },
        Err(err) => return HttpResponse::InternalServerError()
            .body(format!("X-Redirect-URI header error: {}", err))
    };
    let mut auth_store = app_data.session_auth_store.lock().unwrap();

    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_string())
        .expect("fix your code");
    let client = BasicClient::new(
        app_data.google_client_id.clone(),
        Some(app_data.google_client_secret.clone()),
        auth_url,
        TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).ok(),
    )
    .set_redirect_uri(redirect_uri);
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("https://www.googleapis.com/auth/userinfo.email".to_string()))
        .add_scope(Scope::new("openid".to_string()))
        .set_pkce_challenge(pkce_code_challenge)
        .url();
    
    let session_id = Uuid::new_v4().to_string();
    auth_store.insert(
        session_id.clone(),
        AuthorizationSession{
            client,
            source_uri,
            timeout: Instant::now() + Duration::from_secs(1800),
            pkce_code_verifier,
            csrf_state,
        });
    
    HttpResponse::Unauthorized()
        .append_header((header::LOCATION, authorize_url.to_string()))
        .cookie(
            Cookie::build("session_id", session_id.clone())
                .path("/")
                .secure(true)
                .max_age(CDuration::days(1))
                .finish(),
        )
        .finish()
}

fn auth_token_validate(token: &str, app_data: &AppData) -> Result<AuthToken, jsonwebtoken::errors::Error> {
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    let secret = jsonwebtoken::DecodingKey::from_secret(app_data.jwt_secret.secret().as_bytes());
    Ok(decode::<AuthToken>(&token, &secret, &validation)?.claims)
}

#[get("/auth/check")]
async fn check_session(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    let session_id = match get_header_string(&req, "X-Session-Id") {
        Ok(value) => value,
        Err(err) => {
            info!("failed to get X-Session-Id from headers: {}", err);
            return renew_session(req, app_data).await
        },
    };

    match auth_token_validate(&session_id, &app_data) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(err) =>{
            info!("token validation failed: {}", err);
            renew_session(req, app_data.clone()).await
        }
    }
}

async fn clean_expired_auths(auth_store: AuthStore) {
    let mut interval = interval(Duration::from_secs(600));
    loop {
        interval.tick().await;
        debug!("Cleaning expired auths");
        let mut store = auth_store.lock().unwrap();
        store.retain(|_, session| session.timeout > Instant::now());
    }
}

async fn fetch_google_public_keys() -> Result<Vec<DecodingKey>, Box<dyn std::error::Error>> {
    const URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

    let response: serde_json::Value = reqwest::get(URL).await?.json().await?;

    let keys = response["keys"].as_array().ok_or("failed to convert keys to array")?;

    let mut decoded_keys = Vec::new();

    for key in keys {
        let n = key["n"]
            .as_str()
            .ok_or("Failed to convert n to string")?;
        let e = key["e"]
            .as_str()
            .ok_or("Failed to convert e to string")?;

        debug!("Key n: {}, e: {}", n, e);
        use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};

        let n_decoded = URL_SAFE_NO_PAD.decode(n)?;
        let e_decoded = URL_SAFE_NO_PAD.decode(e)?;
        debug!("Key decoded n: {:?}, e: {:?}", n_decoded, e_decoded);

        let decoding_key = DecodingKey::from_rsa_raw_components(
            n_decoded.as_slice(),
            e_decoded.as_slice()
        );
        decoded_keys.push(decoding_key);
    }
    
    Ok(decoded_keys)
}

fn env_var(key: &str) -> Result<String, std::io::Error> {
    let ret = env::var(key).map_err(
        |err| std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Missing the {} environment variable: {}", key, err)
        )
    );
    match ret {
        Ok(s) => {
            if s == "" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Environment variable {} is empty.", key)
                ));
            } else {
                return Ok(s);
            }
        },
        Err(e) => Err(e)
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    let address = env::var("BIND_ADDRESS").unwrap_or("0.0.0.0:8080".to_string());
    let google_client_id = ClientId::new(env_var("GOOGLE_CLIENT_ID")?);
    let google_client_secret = ClientSecret::new(env_var("GOOGLE_CLIENT_SECRET")?);
    let authentication_success_url = env_var("AUTHENTICATION_SUCCESS_URL").unwrap_or("/".to_string());
    let jwt_secret = ClientSecret::new(env_var("JWT_SECRET")?);
    let google_keys = fetch_google_public_keys()
        .await
        .map_err(
            |err| std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Couldn't fetch google public keys: {}", err)
            )
        )?;

    let session_auth_store: AuthStore = Arc::new(Mutex::new(HashMap::new()));
    let app_data = AppData{
        session_auth_store,
        google_client_id,
        google_client_secret,
        authentication_success_url,
        google_keys,
        jwt_secret,
    };

    let cleaner_session_auth_store = app_data.session_auth_store.clone();
    tokio::spawn(async move {
        clean_expired_auths(cleaner_session_auth_store).await;
    });

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
            .app_data(web::Data::new(app_data.clone()))
            .service(check_session)
            .service(login)
    })
    .bind(address)?
    .run()
    .await
}
