mod auth_plugins;
mod util;

use actix_web::{
    get, web, App, HttpServer, Responder, HttpResponse,
    HttpRequest, cookie::Cookie
};
// Alternatively, this can be oauth2::curl::http_client or a custom.
use oauth2::{ClientSecret, RedirectUrl};
use reqwest::header::LOCATION;
use serde::{Serialize, Deserialize};
use std::{time::{UNIX_EPOCH, SystemTime}, collections::HashMap, sync::Arc};
use actix_web::middleware::Logger;
use env_logger::Env;
use std::env;
use jsonwebtoken::{decode, Validation};
use log::{debug, info, error};
use util::{env_var, remove_path_last_part};

use crate::util::get_header_string;

#[derive(Serialize, Debug)]
struct LoginResponse {
    session_id: String,
}

type PluginsOne = std::sync::Arc<std::sync::Mutex<dyn auth_plugins::basic_trait::AuthPlugin>>;
type Plugins = HashMap<String, PluginsOne>;

#[derive(Clone)]
struct AppData {
    authentication_success_url: String,
    jwt_secret: ClientSecret,
    plugins: Plugins,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthToken{
    sub: String,
    exp: u64,
}

fn create_token_cookie<'c>(app_data: web::Data<AppData>, mut token: AuthToken) -> Cookie<'c> {
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
        .max_age(actix_web::cookie::time::Duration::seconds(expiration_seconds.try_into().unwrap()))
        .finish();
}

async fn finalize_login(
    app_data: web::Data<AppData>,
    _req: HttpRequest,
    auth_result: auth_plugins::AuthResult,
) -> HttpResponse {
    debug!("result: {:?}", auth_result);
    let claims = AuthToken {
        sub: format!("{}:{}", auth_result.issuer, auth_result.user),
        exp: 0,
    };

    HttpResponse::Ok()
        .cookie(create_token_cookie(app_data, claims))
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

#[derive(Serialize, Debug)]
struct ErrorResponse {
    error: &'static str,
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
                .cookie(create_token_cookie(app_data, token))
                .finish()
        },
        Err(err) =>{
            info!("token validation failed: {}", err);
            HttpResponse::Unauthorized().json(ErrorResponse { error: "no session found to keep alive" })
        }
    }
}

#[get("/login")]
async fn login(
    _req: HttpRequest,
    app_data: web::Data<AppData>,
) -> HttpResponse {
    let mut html = String::from("<html><head><title>Login</title></head><body><h1>Login</h1><ul>");

    for plugin_name in app_data.plugins.keys() {
        html.push_str(&format!(
            r#"<li><a href="/auth/{plugin_name}">{plugin_name}</a></li>"#,
            plugin_name = plugin_name
        ));
    }

    html.push_str("</ul></body></html>");

    HttpResponse::Ok().content_type("text/html").body(html)
}

async fn forward_to_login(
    req: HttpRequest,
    _app_data: web::Data<AppData>,
) -> HttpResponse {
    let source_uri =match get_header_string(&req, "X-Original-URI") {
        Ok(value) => value,
        Err(err) => return HttpResponse::InternalServerError()
            .body(format!("X-Original-URI header error: {}", err))
    };
    let source_path = remove_path_last_part(source_uri.clone());
    let redirect_uri = match RedirectUrl::new(format!("{}/login",source_path)) {
        Ok(v) => v,
        Err(e) => {
            error!("RedirectUrl parse error: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    HttpResponse::Unauthorized()
        .append_header((actix_web::http::header::LOCATION, redirect_uri.to_string()))
        .finish()
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
            return forward_to_login(req, app_data).await
        },
    };

    match auth_token_validate(&session_id, &app_data) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(err) =>{
            info!("token validation failed: {}", err);
            forward_to_login(req, app_data.clone()).await
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    let address = env::var("BIND_ADDRESS").unwrap_or("0.0.0.0:8080".to_string());
    let authentication_success_url = env_var("AUTHENTICATION_SUCCESS_URL").unwrap_or("/".to_string());
    let jwt_secret = ClientSecret::new(env_var("JWT_SECRET")?);
    let plugins_array: Vec<PluginsOne> = vec![
        Arc::new(std::sync::Mutex::new(auth_plugins::google_auth::init().await?))
    ];
    let mut plugins = Plugins::new();
    for item in plugins_array {
        let item_inner = item.lock().unwrap();
        plugins.insert(item_inner.get_name(), item.clone());
    }
    let app_data = AppData{
        authentication_success_url,
        jwt_secret,
        plugins,
    };
    

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
            .app_data(web::Data::new(app_data.clone()))
            .service(
                web::scope("/auth")
                    .service(check_session)
                    .service(keep_alive)
                    .configure(|cfg| {
                        for item in app_data.plugins.values() {
                            cfg.service(item.lock().unwrap().get_actix_scope());
                        }
                    })
            )
            .service(healthcheck)
    })
    .bind(address)?
    .run()
    .await
}
