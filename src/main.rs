mod auth_plugins;
mod util;
mod database;
mod admin;

use actix_web::{
    get, post, web, App, HttpServer, Responder, HttpResponse,
    HttpRequest, cookie::Cookie
};
use auth_plugins::basic_trait::PluginContainer;
// Alternatively, this can be oauth2::curl::http_client or a custom.
use oauth2::ClientSecret;
use regex::Regex;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use actix_web::middleware::Logger;
use env_logger::Env;
use std::env;
use jsonwebtoken::{decode, Validation};
use log::{debug, info};
use util::{env_var, remove_path_last_part};

use crate::{util::get_header_string, database::User};

const SESSION_COOKIE_NAME: &str = "session_id";
const SESSION_COOKIE_LIFETIME: u64 = 3600;

const LOGIN_COOKIE_NAME: &str = "login_id";
const LOGIN_COOKIE_LIFETIME: u64 = 3600;

const FORWARDED_URI_HEADER: &str = "X-Forwarded-URI";
const FORWARDED_HOST_HEADER: &str = "Host";
const FORWARDED_PROTO_HEADER: &str = "X-Forwarded-Proto";

const ORIGINAL_URI_HEADER: &str = "X-Original-URI";
const ORIGINAL_METHOD_HEADER: &str = "X-Original-Method";
const LOGIN_SUCCESS_HEADER: &str = "X-Login-Success";

const HAS_PERMISSION_HEADER: &str = "X-Has-Permission";

#[derive(Serialize, Debug)]
struct LoginResponse {
    session_id: String,
}

type Plugins = HashMap<String, PluginContainer>;

#[derive(Clone)]
pub struct AppData {
    jwt_secret: ClientSecret,
    plugins: Plugins,
    login_page_override: Option<String>,
    login_success_page: String,
    database: database::Database,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthToken{
    sub: String,
    exp: u64,
    roles: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct LoginJWT{
    sub: String,
    exp: u64,
    location: String,
}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    error: String,
}

pub fn err_internal() -> HttpResponse {
    HttpResponse::InternalServerError()
        .json(ErrorResponse{error:"internal server error".to_string()})
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct Forwarded {
    uri: String,
    path: String,
    host: String,
    proto: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct Original {
    uri: String,
    method: String,
}

macro_rules! cookify_jwt {
    ($app_data:expr, $token:expr, $life_time:expr, $cookie_name:expr) => {{
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() + $life_time;
        $token.exp = exp;

        let secret = jsonwebtoken::EncodingKey::from_secret($app_data.jwt_secret.secret().as_bytes());

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let token_str = jsonwebtoken::encode(&header, &$token, &secret).unwrap();
        Cookie::build($cookie_name, token_str)
            .path("/")
            .secure(true)
            .http_only(true)
            .max_age(actix_web::cookie::time::Duration::seconds($life_time.try_into().unwrap()))
            .finish()
    }};
}

fn parse_forwarded_headers(req: &HttpRequest) -> Result<Forwarded, HttpResponse> {
    fn h(req: &HttpRequest, s: &str) -> Result<String, HttpResponse> {
        get_header_string(req, s)
            .map_err(|err| {log::error!("failed to extract header {}: {}", s, err);err_internal()})
    }
    let uri = h(req, FORWARDED_URI_HEADER)?;
    let proto = h(req, FORWARDED_PROTO_HEADER)?;
    let host = h(req, FORWARDED_HOST_HEADER)?;
    let path = remove_path_last_part(uri.clone());
    Ok(Forwarded {
        uri,
        path,
        host,
        proto,
    })
}

fn parse_original_headers(req: &HttpRequest, forwarded: &Forwarded) -> Original {
    let uri = get_header_string(req, ORIGINAL_URI_HEADER).unwrap_or(forwarded.uri.clone());
    let method = get_header_string(req, ORIGINAL_METHOD_HEADER).unwrap_or("GET".to_string());
    Original {
        uri,
        method,
    }
}

async fn finalize_login(
    app_data: web::Data<AppData>,
    req: HttpRequest,
    auth_result: auth_plugins::AuthResult,
) -> HttpResponse {
    debug!("result: {:?}", auth_result);

    let user = match User::get_by_outer_id(
        app_data.database.clone(),
        auth_result.issuer.clone(),
        auth_result.user.clone(),
    ).await {
        Ok(value) => value,
        Err(err) => match err.downcast_ref::<rusqlite::Error>() {
            Some(rusqlite::Error::QueryReturnedNoRows) => {
                match User::create_new_guest_oauth(
                    app_data.database.clone(),
                    auth_result.issuer.clone(),
                    auth_result.user.clone(),
                ).await {
                    Ok(value) => value,
                    Err(err) => {
                        log::error!("failed to create user: {}", err);
                        return err_internal()
                    }
                }
            }
            _ => {
                log::error!("failed to get user: {}", err);
                return err_internal()
            }
        }
    };
    match user.update_oauth_data(auth_result.data).await {
        Ok(_) => {},
        Err(err) => {
            log::warn!("failed to update user oauth data: {}", err);
        }
    };

    let mut claims = AuthToken {
        sub: user.id.to_string(),
        roles: user.roles.into_iter().collect(),
        exp: 0,
    };

    let after_login = match req.cookie(LOGIN_COOKIE_NAME) {
        Some(cookie) => match token_validate::<LoginJWT>(cookie.value(), &app_data.jwt_secret) {
            Ok(token) => token.location,
            Err(_) => "/".to_string()
        }
        None => "/".to_string()
    };

    HttpResponse::SeeOther()
        .cookie(cookify_jwt!(
            app_data,
            claims,
            SESSION_COOKIE_LIFETIME,
            SESSION_COOKIE_NAME
        ))
        .append_header((actix_web::http::header::LOCATION, after_login))
        .finish()
}

fn token_validate<T: for<'de> serde::Deserialize<'de>>(token: &str, secret: &ClientSecret) -> Result<T, jsonwebtoken::errors::Error> {
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    let secret = jsonwebtoken::DecodingKey::from_secret(secret.secret().as_bytes());
    Ok(decode::<T>(&token, &secret, &validation)?.claims)
}

#[get("/healthcheck")]
async fn healthcheck() -> impl Responder {
    HttpResponse::Ok().finish()
}

fn get_plugin_attrs(plugin: &PluginContainer, forwarded_path: &String) -> Result<(String, String), HttpResponse> {
    let (login_page, name) = match plugin.lock() {
        Err(err) =>{
            log::error!("failed to lock plugin: {}", err);
            return Err(err_internal())
        },
        Ok(plugin) => {
            (plugin.get_login_page(forwarded_path), plugin.get_name())
        }
    };
    let login_page = if login_page.starts_with("/") {
        login_page
    } else {
        format!("{}/{}/{}", forwarded_path, name, login_page)
    };
    Ok((name, login_page))
}

#[get("/login")]
async fn login(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> HttpResponse {
    debug!("request: {:?}", req);
    let forwarded = U!(parse_forwarded_headers(&req));

    if app_data.plugins.len() == 1 {
        let (_name, plugin) = app_data.plugins.iter().next().unwrap();
        let (_name, login_page) = U!(get_plugin_attrs(plugin, &forwarded.path));
        
        return HttpResponse::SeeOther()
            .append_header((actix_web::http::header::LOCATION, login_page))
            .finish();
    }

    let mut html = String::from("<html><head><title>Login</title></head><body><h1>Login</h1><ul>");

    for plugin in app_data.plugins.values() {
        let (name, login_page) = U!(get_plugin_attrs(plugin, &forwarded.path));
        html.push_str(&format!(
            r#"<li><a href="{url}">{name}</a></li>"#,
            url = login_page,
            name = name
        ));
    }

    html.push_str("</ul></body></html>");

    HttpResponse::Ok().content_type("text/html").body(html)
}

#[get("/login_json")]
async fn login_json(
    req: HttpRequest,
    app_data: web::Data<AppData>
) -> HttpResponse {
    debug!("request: {:?}", req);
    let forwarded = U!(parse_forwarded_headers(&req));

    let mut plugins: HashMap<String, String> = HashMap::new();

    for plugin in app_data.plugins.values() {
        let (name, login_page) = U!(get_plugin_attrs(plugin, &forwarded.path));
        plugins.insert(
            name,
            login_page,
        );
    }

    #[derive(Serialize, Clone, Debug)]
    struct Ret {
        plugins: HashMap<String, String>
    }

    HttpResponse::Ok().content_type("application/json").json(Ret{
        plugins
    })
}

#[get("/permissions")]
async fn permissions(
    req: HttpRequest,
    app_data: web::Data<AppData>
) -> HttpResponse {
    debug!("request: {:?}", req);
    let token = U!(check_session(req.clone(), app_data.clone()).await);
    let user = U!(crate::admin::get_current_user(&app_data, &token).await);
    let perms = U!(user.get_permissions().await.map_err(|err| {
        log::error!("failed to get user permissions: {}", err);
        err_internal()
    }));
    let is_su = user.is_su();

    #[derive(Serialize, Clone, Debug)]
    struct Ret {
        permissions: Vec<String>,
        is_su: bool,
    }

    HttpResponse::Ok().content_type("application/json").json(Ret{
        permissions: perms,
        is_su,
    })
}

#[post("/permissions")]
async fn permissions_check(
    req: HttpRequest,
    app_data: web::Data<AppData>,
    permissions_to_check: web::Json<Vec<String>>,
) -> HttpResponse {
    debug!("request: {:?}", req);
    let token = U!(check_session(req.clone(), app_data.clone()).await);
    let user = U!(crate::admin::get_current_user(&app_data, &token).await);
    if user.is_su() {
        return HttpResponse::Ok().content_type("application/json").json(permissions_to_check);
    }

    let perms = U!(user.get_permissions().await.map_err(|err| {
        log::error!("failed to get user permissions: {}", err);
        err_internal()
    }));

    let intersection: Vec<String> = permissions_to_check
        .iter()
        .filter(|element| perms.contains(element))
        .cloned()
        .collect();

    HttpResponse::Ok().content_type("application/json").json(intersection)
}

async fn forward_to_login(
    req: HttpRequest,
    app_data: web::Data<AppData>,
    err: String,
) -> HttpResponse {
    let forwarded = U!(parse_forwarded_headers(&req));
    let originals = parse_original_headers(&req, &forwarded);
    let login_path = match &app_data.login_page_override {
        Some(uri) => format!("{}#{}/login_json", uri, forwarded.path),
        None => format!("{}/login", forwarded.path)
    };
    let login_success_page = if originals.method == "GET" {
        originals.uri
    } else {
        get_header_string(&req, LOGIN_SUCCESS_HEADER).unwrap_or(app_data.login_success_page.clone())
    };

    let mut login_jwt = LoginJWT {
        sub: String::from(""),
        exp: 0,
        location: login_success_page
    };

    HttpResponse::Unauthorized()
        .append_header((actix_web::http::header::LOCATION, login_path))
        .cookie(cookify_jwt!(app_data, login_jwt, LOGIN_COOKIE_LIFETIME, LOGIN_COOKIE_NAME))
        .json(ErrorResponse { error: err })
}

async fn check_session(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> Result<AuthToken, HttpResponse> {
    let session_id = match req.cookie(SESSION_COOKIE_NAME) {
        Some(cookie) => {
            cookie.value().to_string()
        }
        None => {
            return Err(forward_to_login(req, app_data, "no session found".to_string()).await)
        }
    };

    match token_validate::<AuthToken>(&session_id, &app_data.jwt_secret) {
        Ok(token) => {
            Ok(token)
        },
        Err(err) =>{
            info!("token validation failed: {}", err);
            Err(forward_to_login(req, app_data.clone(), "session is not valid".to_string()).await)
        }
    }
}

fn validate_varname_str(input: &str, length: usize) -> bool {
    if 0 < input.len() && input.len() < length {
        return false;
    }
    Regex::new(r"^[A-Za-z0-9_-]+$").unwrap().is_match(input)
}

#[get("/check")]
async fn check(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    debug!("request: {:?}", req);
    let token = U!(check_session(req.clone(), app_data.clone()).await);

    if let Ok(permission) = get_header_string(&req, HAS_PERMISSION_HEADER) {
        if validate_varname_str(&permission, crate::admin::MAX_PERMISSION_LENGTH) {
            let user = U!(crate::admin::get_current_user(&app_data, &token).await);
            U!(crate::admin::permit(&user, &permission).await);
        }
    }

    HttpResponse::Ok().finish()
}

#[get("/keep-alive")]
async fn keep_alive(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    debug!("request: {:?}", req);
    let mut token = U!(check_session(req, app_data.clone()).await);

    HttpResponse::Ok().cookie(cookify_jwt!(
            app_data,
            token,
            SESSION_COOKIE_LIFETIME,
            SESSION_COOKIE_NAME
        )).finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("debug"));
    let args: Vec<String> = env::args().collect();

    let address = env::var("BIND_ADDRESS").unwrap_or("0.0.0.0:8080".to_string());
    let login_page_override = env::var("LOGIN_PAGE_OVERRIDE").ok();
    let login_success_page = env::var("DEFAULT_LOGIN_SUCCESS_PAGE").unwrap_or("/".to_string());
    let jwt_secret = ClientSecret::new(env_var("JWT_SECRET")?);
    let plugins_array: Vec<Option<PluginContainer>> = vec![
        auth_plugins::example_auth::init(&args, false)?,
        auth_plugins::google_auth::init(&args, false).await?,
        auth_plugins::telegram_auth::init(&args, true)?,
    ];
    let mut plugins = Plugins::new();
    for item_opt in plugins_array {
        if let Some(item) = item_opt {
            let item_inner = item.lock().unwrap();
            plugins.insert(item_inner.get_name(), item.clone());
        }
    }
    if plugins.len() < 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("No authorization plugins enabled.")
        ))
    }
    let app_data = AppData{
        jwt_secret,
        plugins,
        login_page_override,
        login_success_page,
        database: database::Database::new().await.map_err(|e|
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to open database: {:?}", e)
            )
        )?
    };
    

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
            .app_data(web::Data::new(app_data.clone()))
            .service(
                web::scope("/auth")
                    .service(admin::init())
                    .service(check)
                    .service(keep_alive)
                    .service(permissions)
                    .service(permissions_check)
                    .service(login)
                    .service(login_json)
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
