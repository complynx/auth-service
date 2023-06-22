use std::collections::HashMap;
use std::sync::{Mutex, Arc};
use std::time::{Duration, Instant};

use actix_web::cookie::Cookie;
use actix_web::http::header;
use actix_web::{web, get, HttpRequest, HttpResponse, Scope, Responder};
use jsonwebtoken::{DecodingKey, Validation};
use log::{debug, info, error};
use oauth2::{ClientId,ClientSecret, RedirectUrl, AuthUrl, CsrfToken, PkceCodeChallenge, TokenUrl, AuthorizationCode};
use serde::{Deserialize, Serialize};
use tokio::time::interval;
use uuid::Uuid;
use const_format::concatcp;

use crate::auth_plugins::basic_trait::get_plugin_data;
use crate::{parse_forwarded_headers, U, err_internal};

use super::super::{finalize_login, AppData};
use super::super::util::{env_var};

#[derive(Debug)]
struct AuthorizationSession {
    client: GoogleClient,
    timeout: Instant,
    pkce_code_verifier: oauth2::PkceCodeVerifier,
    csrf_state: CsrfToken,
}

type AuthStore = Arc<Mutex<HashMap<String, AuthorizationSession>>>;

use super::basic_trait::{AuthPlugin, PluginContainer, flag};
#[derive(Clone)]
struct GoogleAuth {
    client_id: ClientId,
    client_secret: ClientSecret,
    keys: Vec<DecodingKey>,
    sessions: AuthStore,
}
const GOOGLE_AUTH_NAME: &str = "google";
const GOOGLE_AUTH_PATH: &str = concatcp!("/", GOOGLE_AUTH_NAME);
const GOOGLE_LOGIN_PAGE: &str = "login";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GoogleExtraTokenFields {
    pub id_token: String,
}

impl oauth2::ExtraTokenFields for GoogleExtraTokenFields {}

pub type GoogleTokenResponse = oauth2::StandardTokenResponse<GoogleExtraTokenFields, oauth2::basic::BasicTokenType>;
pub type GoogleClient = oauth2::Client<
    oauth2::basic::BasicErrorResponse,
    GoogleTokenResponse,
    oauth2::basic::BasicTokenType,
    oauth2::basic::BasicTokenIntrospectionResponse,
    oauth2::StandardRevocableToken,
    oauth2::basic::BasicRevocationErrorResponse,
>;

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct GoogleToken {
    sub: String,
    email: String,
}

#[derive(Deserialize, Debug)]
struct CodeResponse {
    code: String,
    state: String
}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    error: &'static str,
}

impl AuthPlugin for GoogleAuth {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn get_name(&self) -> String {
        String::from(GOOGLE_AUTH_NAME)
    }

    fn get_login_page(&self, _path: &String) -> String {
        String::from(GOOGLE_LOGIN_PAGE)
    }
    
    fn get_actix_scope(&self) -> Scope {
        web::scope(GOOGLE_AUTH_PATH)
            .service(login)
            .service(stage2)
    }
}

fn validate_google_token(plugin: &GoogleAuth, token: &str) -> Result<GoogleToken, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[&plugin.client_id.as_str()]);
    validation.set_issuer(&["accounts.google.com", "https://accounts.google.com"]);

    for key in &plugin.keys {
        match jsonwebtoken::decode::<GoogleToken>(token, key, &validation) {
            Ok(decoded_token) => {
                return Ok(decoded_token.claims);
            },
            Err(err) => {
                debug!("decode token failed: {} ({:?})", err, err.kind());
            }
        }
    }

    Err(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken))
}

#[get("/login")]
async fn login(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> HttpResponse {
    debug!("request: {:?}", req);
    let forwarded = U!(parse_forwarded_headers(&req));
    let redirect_uri = match RedirectUrl::new(format!(
        "{}://{}{}/stage2",
        forwarded.proto,
        forwarded.host,
        forwarded.path
    )) {
        Ok(v) => v,
        Err(e) => {
            error!("RedirectUrl parse error: {}", e);
            return err_internal();
        }
    };
    let plugin = U!(get_plugin_data::<GoogleAuth>(&app_data, GOOGLE_AUTH_NAME));

    let mut auth_store = plugin.sessions.lock().unwrap();

    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_string())
        .expect("fix your code");
    let client = GoogleClient::new(
        plugin.client_id.clone(),
        Some(plugin.client_secret.clone()),
        auth_url,
        TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).ok(),
    ).set_redirect_uri(redirect_uri);
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(oauth2::Scope::new("https://www.googleapis.com/auth/userinfo.email".to_string()))
        .add_scope(oauth2::Scope::new("openid".to_string()))
        .set_pkce_challenge(pkce_code_challenge)
        .url();
    
    let session_id = Uuid::new_v4().to_string();
    auth_store.insert(
        session_id.clone(),
        AuthorizationSession{
            client,
            timeout: Instant::now() + Duration::from_secs(1800),
            pkce_code_verifier,
            csrf_state,
        });
    
    HttpResponse::SeeOther()
        .append_header((header::LOCATION, authorize_url.to_string()))
        .cookie(
            Cookie::build("google_auth_session_id", session_id.clone())
                .path(forwarded.path)
                .secure(true)
                .http_only(true)
                .max_age(actix_web::cookie::time::Duration::days(1))
                .finish(),
        )
        .finish()
}

#[get("/stage2")]
async fn stage2(
    req: HttpRequest,
    web::Query(data): web::Query<CodeResponse>,
    app_data: web::Data<AppData>,
) -> impl Responder {
    debug!("request: {:?}", req);
    let session_id = match req.cookie("google_auth_session_id") {
        Some(cookie) => {
            cookie.value().to_string()
        }
        None => {
            info!("cookie google_auth_session_id not found");
            return HttpResponse::Unauthorized().json(ErrorResponse { error: "No cookie google_auth_session_id" })
        }
    };
    let code = AuthorizationCode::new(data.code);
    let state = CsrfToken::new(data.state);

    let plugin = U!(get_plugin_data::<GoogleAuth>(&app_data, GOOGLE_AUTH_NAME));
    let mut auth_store = plugin.sessions.lock().unwrap();

    if let Some(auth_data) = auth_store.remove(session_id.as_str()) {
        if auth_data.timeout > Instant::now() {
            if state.secret() != auth_data.csrf_state.secret() {
                return HttpResponse::Unauthorized().json(ErrorResponse { error: "State mismatch" });
            }
            let token_response = auth_data.client
                .exchange_code(code)
                .set_pkce_verifier(auth_data.pkce_code_verifier)
                .request_async(oauth2::reqwest::async_http_client)
                .await;

            match token_response {
                Ok(token_response_unwrapped) => {
                    match validate_google_token(&plugin, token_response_unwrapped.extra_fields().id_token.as_str()) {
                        Ok(token) => finalize_login(app_data.clone(), req, super::AuthResult{
                            user: token.sub,
                            issuer: plugin.get_name(),
                            data: serde_json::json!({
                                "email": token.email.clone()
                            }),
                        }).await,
                        Err(err) => {
                            info!("google token validation failed {}", err);
                            HttpResponse::Unauthorized()
                                .json(ErrorResponse { error: "Google JWT validation failed" })
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

        let decoding_key = DecodingKey::from_rsa_components(n,e)?;
        decoded_keys.push(decoding_key);
    }
    
    Ok(decoded_keys)
}

async fn clean_expired_auths(auth_store: AuthStore) {
    let mut interval = interval(Duration::from_secs(600));
    loop {
        interval.tick().await;
        debug!("Cleaning expired google auths");
        let mut store = auth_store.lock().unwrap();
        store.retain(|_, session| session.timeout > Instant::now());
    }
}

pub async fn init(args: &Vec<String>, default_enabled: bool) -> Result<Option<PluginContainer>, std::io::Error> {
    if !flag(args, GOOGLE_AUTH_NAME, default_enabled) {
        return Ok(None);
    }

    let client_id = ClientId::new(env_var("GOOGLE_CLIENT_ID")?);
    let client_secret = ClientSecret::new(env_var("GOOGLE_CLIENT_SECRET")?);

    let keys = fetch_google_public_keys()
        .await
        .map_err(
            |err| std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Couldn't fetch google public keys: {}", err)
            )
        )?;
    let sessions: AuthStore = Arc::new(Mutex::new(HashMap::new()));
    
    let cleaner_session_auth_store = sessions.clone();
    tokio::spawn(async move {
        clean_expired_auths(cleaner_session_auth_store).await;
    });

    Ok(Some(std::sync::Arc::new(std::sync::Mutex::new(GoogleAuth{
        client_id,
        client_secret,
        keys,
        sessions,
    }))))
}
