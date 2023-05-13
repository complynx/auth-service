
use actix_web::{web, get, HttpRequest, HttpResponse, Scope};
use const_format::concatcp;
use serde::{Serialize, Deserialize};
use crate::util::env_var;
use crate::{parse_forwarded_headers, U};
use crate::auth_plugins::basic_trait::get_plugin_data;
use super::super::{finalize_login, AppData};
use super::basic_trait::{AuthPlugin, PluginContainer, flag};

const TELEGRAM_AUTH_NAME: &str = "telegram";
const TELEGRAM_AUTH_PATH: &str = concatcp!("/", TELEGRAM_AUTH_NAME);
const TELEGRAM_LOGIN_PAGE: &str = "login";
const MAX_AUTH_RECEIVE_DURATION: std::time::Duration = std::time::Duration::from_secs(5 * 60);

#[derive(Clone)]
struct TelegramAuth {
    bot_name: String,
    bot_token: String,
    login_page_override: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TelegramLoginResponse {
    id: String,
    first_name: String,
    last_name: String,
    username: String,
    photo_url: String,
    auth_date: String,
    hash: String,
}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    error: &'static str,
}

impl AuthPlugin for TelegramAuth {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn get_name(&self) -> String {
        String::from(TELEGRAM_AUTH_NAME)
    }

    fn get_login_page(&self, path: &String) -> String {
        match self.login_page_override.clone() {
            Some(v) => format!("{}#{}/{}/login_json", v, path, TELEGRAM_AUTH_NAME),
            None => String::from(TELEGRAM_LOGIN_PAGE)
        }
    }
    
    fn get_actix_scope(&self) -> Scope {
        web::scope(TELEGRAM_AUTH_PATH)
            .service(stage1)
            .service(stage2)
            .service(stage1_json)
    }
}

pub fn init(args: &Vec<String>, default_enabled: bool) -> Result<Option<PluginContainer>, std::io::Error> {
    if !flag(args, TELEGRAM_AUTH_NAME, default_enabled) {
        return Ok(None);
    }
    let bot_name = env_var("TELEGRAM_LOGIN_BOT_ID")?;
    let bot_token = env_var("TELEGRAM_LOGIN_BOT_TOKEN")?;
    let login_page_override = std::env::var("TELEGRAM_LOGIN_PAGE_OVERRIDE").ok();

    Ok(Some(std::sync::Arc::new(std::sync::Mutex::new(TelegramAuth{
        bot_name,
        bot_token,
        login_page_override,
    }))))
}

#[get("/login")]
async fn stage1(
    app_data: web::Data<AppData>,
    req: HttpRequest,
) -> HttpResponse {
    log::debug!("request: {:?}", req);
    let plugin = U!(get_plugin_data::<TelegramAuth>(&app_data, TELEGRAM_AUTH_NAME));
    let mut html = String::from("<html><head><title>Login to telegram</title></head><body><h1>Login to telegram</h1><ul>");
    let forwarded = U!(parse_forwarded_headers(&req));
    let uri = format!("{}://{}{}/stage2",
        forwarded.proto,
        forwarded.host,
        forwarded.path,
    );

    html.push_str(&format!(
        r#"<script async src="https://telegram.org/js/telegram-widget.js?22"
                data-telegram-login="{bot_name}"
                data-size="large"
                data-auth-url="{uri}"
                data-request-access="write"></script>"#,
            bot_name=plugin.bot_name,
            uri=uri,
        ).as_str());

    html.push_str("</ul></body></html>");

    
    HttpResponse::Ok().content_type("text/html").body(html)
}

#[get("/login_json")]
async fn stage1_json(
    app_data: web::Data<AppData>,
    req: HttpRequest,
) -> HttpResponse {
    #[derive(Serialize, Clone, Debug)]
    struct Ret {
        url: String,
        bot_name: String,
    }

    log::debug!("request: {:?}", req);
    let plugin = U!(get_plugin_data::<TelegramAuth>(&app_data, TELEGRAM_AUTH_NAME));
    let forwarded = U!(parse_forwarded_headers(&req));
    let uri = format!("{}:/{}{}/stage2",
        forwarded.proto,
        forwarded.host,
        forwarded.path,
    );

    
    HttpResponse::Ok().content_type("application/json").json(Ret{
        url: uri,
        bot_name: plugin.bot_name,
    })
}

pub fn check_hash(data: &TelegramLoginResponse, secret: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::collections::BTreeMap;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC any size");
    let mut map = BTreeMap::new();
    map.insert("id", &data.id);
    map.insert("first_name", &data.first_name);
    map.insert("last_name", &data.last_name);
    map.insert("username", &data.username);
    map.insert("photo_url", &data.photo_url);
    map.insert("auth_date", &data.auth_date);

    let mut check_arr: Vec<String> = map.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
    check_arr.sort();
    let check_string = check_arr.join("\n");
    log::debug!("check string:\n{}",check_string);

    mac.update(check_string.as_bytes());
    let result = mac.finalize();
    let calculated_hash = hex::encode(result.into_bytes());
    log::debug!("calculated hash {}, received hash {}", calculated_hash, data.hash);

    calculated_hash == data.hash
}

#[get("/stage2")]
async fn stage2(
    app_data: web::Data<AppData>,
    req: HttpRequest,
    info: web::Query<TelegramLoginResponse>,
) -> HttpResponse {
    log::debug!("request: {:?}", req);
    let plugin = U!(get_plugin_data::<TelegramAuth>(&app_data, TELEGRAM_AUTH_NAME));

    use std::time::{SystemTime, UNIX_EPOCH};

    if !check_hash(&info, &plugin.bot_token.as_str()) {
        return HttpResponse::Unauthorized().json(ErrorResponse { error: "telegram hash mismatch"});
    }

    let auth_date = match info.auth_date.parse::<u64>() {
        Ok(v) => UNIX_EPOCH + std::time::Duration::from_secs(v),
        Err(_) => return HttpResponse::Unauthorized().json(ErrorResponse { error: "telegram auth_date unparsable"}),
    };
    let now = SystemTime::now();
    match now.duration_since(auth_date) {
        Ok(elapsed) => {
            if elapsed > MAX_AUTH_RECEIVE_DURATION {
                return HttpResponse::Unauthorized().json(ErrorResponse { error: "telegram auth_date too old"});
            }
        }
        Err(_) => return HttpResponse::Unauthorized().json(ErrorResponse { error: "telegram auth_date is in the future"})
    }

    finalize_login(app_data, req, super::AuthResult{
        user: info.id.clone(),
        issuer: TELEGRAM_AUTH_NAME.to_string()
    }).await
}
