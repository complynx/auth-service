
pub trait AuthPlugin {
    fn get_name(&self) -> String;
    fn get_actix_scope(&self) -> actix_web::Scope;
}
