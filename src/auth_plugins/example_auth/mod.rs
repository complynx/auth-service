use actix_web::{web, get, HttpRequest, HttpResponse, Scope};
use super::super::{finalize_login, AppData};


fn init() -> Scope {
    web::scope("/example_auth")
        .service(authenticate)
}

#[get("/authenticate")]
async fn authenticate(
    app_data: web::Data<AppData>,
    req: HttpRequest,
) -> HttpResponse {
    // some code
    finalize_login(app_data, req).await
}
