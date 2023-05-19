use actix_web::{web, get, HttpRequest, HttpResponse, Scope};
use const_format::concatcp;
use crate::U;
use crate::auth_plugins::basic_trait::get_plugin_data;

use super::super::{finalize_login, AppData};

use super::basic_trait::{AuthPlugin, PluginContainer, flag};
#[derive(Clone)]
struct ExampleAuth {
}
const EXAMPLE_AUTH_NAME: &str = "example";
const EXAMPLE_AUTH_PATH: &str = concatcp!("/", EXAMPLE_AUTH_NAME);
const EXAMPLE_LOGIN_PAGE: &str = "login";

impl AuthPlugin for ExampleAuth {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn get_name(&self) -> String {
        String::from(EXAMPLE_AUTH_NAME)
    }

    fn get_login_page(&self, _path: &String) -> String {
        String::from(EXAMPLE_LOGIN_PAGE)
    }
    
    fn get_actix_scope(&self) -> Scope {
        web::scope(EXAMPLE_AUTH_PATH)
            .service(authenticate)
    }
}

pub fn init(args: &Vec<String>, default_enabled: bool) -> Result<Option<PluginContainer>, std::io::Error> {
    if !flag(args, EXAMPLE_AUTH_NAME, default_enabled) {
        return Ok(None);
    }
    Ok(Some(std::sync::Arc::new(std::sync::Mutex::new(ExampleAuth{}))))
}

#[get("/login")]
async fn authenticate(
    app_data: web::Data<AppData>,
    req: HttpRequest,
) -> HttpResponse {
    log::debug!("request: {:?}", req);
    let _plugin = U!(get_plugin_data::<ExampleAuth>(&app_data, EXAMPLE_AUTH_NAME));
    // some code
    finalize_login(app_data, req, super::AuthResult{
        user: "none".to_string(),
        issuer: "stub".to_string(),
        data: serde_json::Value::Null,
    }).await
}
