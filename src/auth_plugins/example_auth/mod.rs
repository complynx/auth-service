use actix_web::{web, get, HttpRequest, HttpResponse, Scope};
use const_format::concatcp;
use super::super::{finalize_login, AppData};

use super::basic_trait::{AuthPlugin, PluginContainer};
#[derive(Clone)]
struct ExampleAuth {
}
const EXAMPLE_AUTH_NAME: &str = "example_auth";
const EXAMPLE_AUTH_PATH: &str = concatcp!("/", EXAMPLE_AUTH_NAME);

impl AuthPlugin for ExampleAuth {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn get_name(&self) -> String {
        String::from(EXAMPLE_AUTH_NAME)
    }
    
    fn get_actix_scope(&self) -> Scope {
        web::scope(EXAMPLE_AUTH_PATH)
            .service(authenticate)
    }
}

pub fn init() -> Result<PluginContainer, std::io::Error> {
    Ok(std::sync::Arc::new(std::sync::Mutex::new(ExampleAuth{})))
}

#[get("/login")]
async fn authenticate(
    app_data: web::Data<AppData>,
    req: HttpRequest,
) -> HttpResponse {
    // some code
    finalize_login(app_data, req, super::AuthResult{
        user: "none".to_string(),
        issuer: "stub".to_string()
    }).await
}
