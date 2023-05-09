mod auth_plugins;
mod util;

use actix_web::{
    get, web, App, HttpServer, Responder, HttpResponse,
    HttpRequest, cookie::Cookie, cookie::time::Duration as CDuration,
    http::header
};
// Alternatively, this can be oauth2::curl::http_client or a custom.
use oauth2::{ClientSecret};
use serde::{Serialize, Deserialize};
use std::time::{UNIX_EPOCH, SystemTime};
use actix_web::middleware::Logger;
use env_logger::Env;
use std::env;
use jsonwebtoken::{decode, Validation};
use log::{debug, info};
use util::env_var;

use crate::util::get_header_string;

#[derive(Serialize, Debug)]
struct LoginResponse {
    session_id: String,
}

#[derive(Clone)]
struct AppData {
    authentication_success_url: String,
    jwt_secret: ClientSecret,
    google_data: auth_plugins::google_auth::GoogleAuth,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthToken{
    sub: String,
    exp: u64,
    email: String,
}

fn create_token_cookie(app_data: &AppData, mut token: AuthToken) -> Cookie {
    let expiration_seconds = 3600;
    let exp = SystemTime::now().duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() + expiration_seconds;

    token.exp = exp;

    let secret = jsonwebtoken::EncodingKey::from_secret(app_data.jwt_secret.secret().as_bytes());

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let auth_token = jsonwebtoken::encode(&header, &token, &secret).unwrap();

    return Cookie::build("session_id", auth_token)
        .path("/")
        .secure(true)
        .max_age(CDuration::seconds(expiration_seconds.try_into().unwrap()))
        .finish();
}

fn finish_login(app_data: &AppData, source_uri: String, token: GoogleToken) -> HttpResponse {
    debug!("google token: {:?}", token);
    let claims = AuthToken {
        sub: token.sub.clone(),
        email: token.email.clone(),
        exp: 0,
    };

    HttpResponse::Found()
        .cookie(create_token_cookie(app_data, claims))
        .append_header((header::LOCATION, source_uri))
        .finish()
}

async fn finalize_login(
    _app_data: web::Data<AppData>,
    _req: HttpRequest,
) -> HttpResponse {
    HttpResponse::Ok()
        .finish()
}

fn auth_token_validate(token: &str, app_data: &AppData) -> Result<AuthToken, jsonwebtoken::errors::Error> {
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    let secret = jsonwebtoken::DecodingKey::from_secret(app_data.jwt_secret.secret().as_bytes());
    Ok(decode::<AuthToken>(&token, &secret, &validation)?.claims)
}

#[get("/healthcheck")]
async fn healthcheck() -> impl Responder {
    HttpResponse::Ok().finish()
}

#[get("/keep-alive")]
async fn keep_alive(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    let session_id = match get_header_string(&req, "X-Session-Id") {
        Ok(value) => value,
        Err(err) => {
            info!("failed to get X-Session-Id from headers: {}", err);
            return HttpResponse::Unauthorized().json(ErrorResponse { error: "no session found to keep alive" })
        },
    };

    match auth_token_validate(&session_id, &app_data) {
        Ok(token) => {
            HttpResponse::Ok()
                .cookie(create_token_cookie(&app_data, token))
                .finish()
        },
        Err(err) =>{
            info!("token validation failed: {}", err);
            HttpResponse::Unauthorized().json(ErrorResponse { error: "no session found to keep alive" })
        }
    }
}

async fn start_login(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> HttpResponse {

}

#[get("/check")]
async fn check_session(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    let session_id = match get_header_string(&req, "X-Session-Id") {
        Ok(value) => value,
        Err(err) => {
            info!("failed to get X-Session-Id from headers: {}", err);
            return start_login(req, app_data).await
        },
    };

    match auth_token_validate(&session_id, &app_data) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(err) =>{
            info!("token validation failed: {}", err);
            start_login(req, app_data.clone()).await
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    let address = env::var("BIND_ADDRESS").unwrap_or("0.0.0.0:8080".to_string());
    let authentication_success_url = env_var("AUTHENTICATION_SUCCESS_URL").unwrap_or("/".to_string());
    let jwt_secret = ClientSecret::new(env_var("JWT_SECRET")?);

    let app_data = AppData{
        authentication_success_url,
        jwt_secret,
        google_data: auth_plugins::google_auth::init().await?,
    };

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
            .app_data(web::Data::new(app_data.clone()))
            .service(web::scope("/auth")
                .service(auth_plugins::google_auth::get_actix_scope())
                .service(check_session)
                .service(keep_alive)
            )
            .service(healthcheck)
    })
    .bind(address)?
    .run()
    .await
}
