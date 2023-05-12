mod auth_plugins;
mod util;

use actix_web::{
    get, web, App, HttpServer, Responder, HttpResponse,
    HttpRequest, cookie::Cookie
};
// Alternatively, this can be oauth2::curl::http_client or a custom.
use oauth2::{ClientSecret};
use serde::{Serialize, Deserialize};
use std::{time::{UNIX_EPOCH, SystemTime}, collections::HashMap};
use actix_web::middleware::Logger;
use env_logger::Env;
use std::env;
use jsonwebtoken::{decode, Validation};
use log::{debug, info};
use util::{env_var, remove_path_last_part};

use crate::util::get_header_string;

const SESSION_COOKIE_NAME: &str = "session_id";
const SESSION_COOKIE_HEADER: &str = "X-Session-Id";

const FORWARDED_URI_HEADER: &str = "X-Forwarded-URI";
const FORWARDED_HOST_HEADER: &str = "Host";
const FORWARDED_PROTO_HEADER: &str = "X-Forwarded-Proto";

const ORIGINAL_URI_HEADER: &str = "X-Original-URI";
const ORIGINAL_METHOD_HEADER: &str = "X-Original-Method";

#[derive(Serialize, Debug)]
struct LoginResponse {
    session_id: String,
}

type PluginsOne = std::sync::Arc<std::sync::Mutex<dyn auth_plugins::basic_trait::AuthPlugin>>;
type Plugins = HashMap<String, PluginsOne>;

#[derive(Clone)]
pub struct AppData {
    jwt_secret: ClientSecret,
    plugins: Plugins,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthToken{
    sub: String,
    exp: u64,
}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    error: String,
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

fn create_token_cookie<'c>(app_data: web::Data<AppData>, mut token: AuthToken) -> Cookie<'c> {
    let expiration_seconds = 3600;
    let exp = SystemTime::now().duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() + expiration_seconds;

    token.exp = exp;

    let secret = jsonwebtoken::EncodingKey::from_secret(app_data.jwt_secret.secret().as_bytes());

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let auth_token = jsonwebtoken::encode(&header, &token, &secret).unwrap();

    return Cookie::build(SESSION_COOKIE_NAME, auth_token)
        .path("/")
        .secure(true)
        .http_only(true)
        .max_age(actix_web::cookie::time::Duration::seconds(expiration_seconds.try_into().unwrap()))
        .finish();
}

fn parse_forwarded_headers(req: &HttpRequest) -> Result<Forwarded, HttpResponse> {
    fn h(req: &HttpRequest, s: &str) -> Result<String, HttpResponse> {
        get_header_string(req, s)
            .map_err(|err| HttpResponse::InternalServerError().body(format!("{} header error: {}", s, err)))
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

#[get("/login")]
async fn login(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> HttpResponse {
    debug!("request: {:?}", req);
    let mut html = String::from("<html><head><title>Login</title></head><body><h1>Login</h1><ul>");
    let forwarded = U!(parse_forwarded_headers(&req));

    for plugin_name in app_data.plugins.keys() {
        html.push_str(&format!(
            r#"<li><a href="{source_path}/{plugin_name}/login">{plugin_name}</a></li>"#,
            plugin_name = plugin_name,
            source_path = forwarded.path
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

    for plugin_name in app_data.plugins.keys() {
        plugins.insert(
            plugin_name.clone(),
            format!("{}/{}", forwarded.path, plugin_name),
        );
    }

    HttpResponse::Ok().content_type("application/json").json(plugins)
}

async fn forward_to_login(
    req: HttpRequest,
    _app_data: web::Data<AppData>,
    err: String,
) -> HttpResponse {
    let forwarded = U!(parse_forwarded_headers(&req));
    let _originals = parse_original_headers(&req, &forwarded);

    HttpResponse::Unauthorized()
        .append_header((actix_web::http::header::LOCATION, format!("{}/login", forwarded.path)))
        .json(ErrorResponse { error: err })
}

async fn check_session_and_keep(
    do_keep_alive: bool,
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    let session_id = match get_header_string(&req, SESSION_COOKIE_HEADER) {
        Ok(value) => value,
        Err(_) => {
            return forward_to_login(req, app_data, "no session found".to_string()).await
        },
    };

    match auth_token_validate(&session_id, &app_data) {
        Ok(token) => {
            let mut builder = HttpResponse::Ok();
            if do_keep_alive {
                builder.cookie(create_token_cookie(app_data, token));
            }
            builder.finish()
        },
        Err(err) =>{
            info!("token validation failed: {}", err);
            forward_to_login(req, app_data.clone(), "session is not valid".to_string()).await
        }
    }
}

#[get("/check")]
async fn check_session(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    debug!("request: {:?}", req);
    check_session_and_keep(false, req, app_data).await
}

#[get("/keep-alive")]
async fn keep_alive(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    debug!("request: {:?}", req);
    check_session_and_keep(true, req, app_data).await
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    let address = env::var("BIND_ADDRESS").unwrap_or("0.0.0.0:8080".to_string());
    let jwt_secret = ClientSecret::new(env_var("JWT_SECRET")?);
    let plugins_array: Vec<PluginsOne> = vec![
        auth_plugins::example_auth::init()?,
        auth_plugins::google_auth::init().await?
    ];
    let mut plugins = Plugins::new();
    for item in plugins_array {
        let item_inner = item.lock().unwrap();
        plugins.insert(item_inner.get_name(), item.clone());
    }
    let app_data = AppData{
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
