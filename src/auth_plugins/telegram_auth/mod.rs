use actix_web::{web, get, HttpRequest, HttpResponse, Scope};
use const_format::concatcp;
use serde::Serialize;
use crate::util::env_var;
use crate::{parse_forwarded_headers, U};
use crate::auth_plugins::basic_trait::get_plugin_data;

use super::super::{finalize_login, AppData};

use super::basic_trait::{AuthPlugin, PluginContainer, flag};
#[derive(Clone)]
struct TelegramAuth {
    bot_name: String,
    bot_token: String,
    login_page_override: Option<String>,
}
const TELEGRAM_AUTH_NAME: &str = "telegram";
const TELEGRAM_AUTH_PATH: &str = concatcp!("/", TELEGRAM_AUTH_NAME);
const TELEGRAM_LOGIN_PAGE: &str = "login";

impl AuthPlugin for TelegramAuth {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn get_name(&self) -> String {
        String::from(TELEGRAM_AUTH_NAME)
    }

    fn get_login_page(&self) -> String {
        match self.login_page_override.clone() {
            Some(v) => v,
            None => String::from(TELEGRAM_LOGIN_PAGE)
        }
    }
    
    fn get_actix_scope(&self) -> Scope {
        web::scope(TELEGRAM_AUTH_PATH)
            .service(stage1)
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

#[get("/stage2")]
async fn stage2(
    app_data: web::Data<AppData>,
    req: HttpRequest,
) -> HttpResponse {
    log::debug!("request: {:?}", req);
    finalize_login(app_data, req, super::AuthResult{
        user: "none".to_string(),
        issuer: "stub".to_string()
    }).await
}
