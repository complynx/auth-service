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
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;
use actix_web::middleware::Logger;
use env_logger::Env;
use tokio::time::interval;
use std::env;
use jsonwebtoken::{decode, DecodingKey, Validation};

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


type SessionStore = Arc<Mutex<HashMap<String, (String, Instant)>>>;
type AuthStore = Arc<Mutex<HashMap<String, AuthorizationSession>>>;

#[derive(Debug, Clone)]
struct AppData {
    session_store: SessionStore,
    session_auth_store: AuthStore,
    google_client_id: ClientId,
    google_client_secret: ClientSecret,
    authentication_success_url: String,
}

fn get_google_email(token: &oauth2::AccessToken) -> Result<String, Box<dyn std::error::Error>> {
    let decoded_id_token = decode::<Value>(
        token.secret(),
        &DecodingKey::from_secret("".as_ref()),
        &Validation::default(),
    )?;

    let email = decoded_id_token
        .claims
        .get("email")
        .and_then(|email| email.as_str())
        .ok_or("No email found for the user")?
        .to_string();

    Ok(email)
}

#[get("/auth/login")]
async fn login(
    req: HttpRequest,
    web::Query(data): web::Query<CodeResponse>,
    app_data: web::Data<AppData>,
) -> impl Responder {
    let session_id = match req.headers().get("X-Session-Id") {
        Some(value) => match value.to_str() {
            Ok(value) => value.to_string(),
            Err(_) => return HttpResponse::Unauthorized().json(ErrorResponse { error: "Bad session ID" }),
        },
        None => return HttpResponse::Unauthorized().json(ErrorResponse { error: "No session ID" }),
    };
    let code =  AuthorizationCode::new(data.code);
    let state =  CsrfToken::new(data.state);

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
                    let email_result = get_google_email(token_response_unwrapped.access_token());
                    match email_result {
                        Ok(email) => {
                            HttpResponse::Found()
                                .append_header(("X-Authenticated-User", email.clone()))
                                .append_header((header::LOCATION, auth_data.source_uri))
                                .finish()
                        },
                        Err(_) => HttpResponse::InternalServerError()
                            .json(ErrorResponse { error: "No email found in the JWT"})
                    }
                },
                Err(_) => HttpResponse::Unauthorized()
                    .json(ErrorResponse { error: "failed to prove token" })
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

    let source_method = match req.headers().get("X-Original-Method") {
        Some(value) => value.to_str().unwrap_or("GET"),
        None => "GET",
    };
    let source_uri = match source_method {
        "GET" => match req.headers().get("X-Original-URI") {
            Some(value) => value.to_str().unwrap_or(app_data.authentication_success_url.as_str()),
            None => app_data.authentication_success_url.as_str(),
        },
        _ => app_data.authentication_success_url.as_str()
    };
    let redirect_uri = match req.headers().get("X-Redirect-URI") {
        Some(value) => match value.to_str() {
            Ok(value) => match RedirectUrl::new(value.to_string()) {
                Ok(value) => value,
                Err(err) => return HttpResponse::InternalServerError()
                    .body(format!("X-Redirect-URI parse error: {}", err))
            },
            Err(err) => return HttpResponse::InternalServerError()
                .body(format!("X-Redirect-URI not a string: {}", err))
        },
        None => return HttpResponse::InternalServerError().body("redirect_uri not provided")
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
            source_uri: source_uri.to_string(),
            timeout: Instant::now() + Duration::from_secs(1800),
            pkce_code_verifier,
            csrf_state,
        });
    
    HttpResponse::Found()
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

#[get("/auth/check")]
async fn check_session(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    let session_id = match req.headers().get("X-Session-Id") {
        Some(value) => match value.to_str() {
            Ok(value) => value.to_string(),
            Err(_) => return renew_session(req, app_data).await,
        },
        None => return renew_session(req, app_data).await,
    };
    
    let mut store = app_data.session_store.lock().unwrap();
    if let Some((username, expiration)) = store.get_mut(&session_id) {
        if *expiration > Instant::now() {
            *expiration = Instant::now() + Duration::from_secs(3600);
            return HttpResponse::Ok().append_header(("X-Authenticated-User", username.clone())).finish();
        } else {
            store.remove(&session_id);
        }
    }
    
    return renew_session(req, app_data.clone()).await
}

async fn clean_expired_sessions(session_store: SessionStore) {
    let mut interval = interval(Duration::from_secs(600));
    loop {
        interval.tick().await;
        let mut store = session_store.lock().unwrap();
        store.retain(|_, (_, expiration)| *expiration > Instant::now());
    }
}

async fn clean_expired_auths(auth_store: AuthStore) {
    let mut interval = interval(Duration::from_secs(600));
    loop {
        interval.tick().await;
        let mut store = auth_store.lock().unwrap();
        store.retain(|_, session| session.timeout > Instant::now());
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let address = env::var("BIND_ADDRESS").unwrap_or("0.0.0.0:8080".to_string());
    let google_client_id = ClientId::new(
        env::var("GOOGLE_CLIENT_ID").map_err(
            |_| std::io::Error::new(
                std::io::ErrorKind::Other,
                "Missing the GOOGLE_CLIENT_ID environment variable."
            )
        )?,
    );
    let google_client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET").map_err(
            |_| std::io::Error::new(
                std::io::ErrorKind::Other,
                "Missing the GOOGLE_CLIENT_SECRET environment variable."
            )
        )?,
    );
    let authentication_success_url = env::var("AUTHENTICATION_SUCCESS_URL").map_err(
        |_| std::io::Error::new(
            std::io::ErrorKind::Other,
            "Missing the AUTHENTICATION_SUCCESS_URL environment variable."
        )
    )?;

    let session_store: SessionStore = Arc::new(Mutex::new(HashMap::new()));
    let session_auth_store: AuthStore = Arc::new(Mutex::new(HashMap::new()));
    let app_data = AppData{
        session_store,
        session_auth_store,
        google_client_id,
        google_client_secret,
        authentication_success_url,
    };

    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    let cleaner_session_store = app_data.session_store.clone();
    tokio::spawn(async move {
        clean_expired_sessions(cleaner_session_store).await;
    });
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
