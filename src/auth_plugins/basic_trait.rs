
pub trait AuthPlugin: Send {
    fn get_name(&self) -> String;
    fn get_actix_scope(&self) -> actix_web::Scope;
    fn as_any(&self) -> &dyn std::any::Any;
}

