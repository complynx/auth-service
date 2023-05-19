use actix_web::HttpResponse;

use crate::err_internal;


pub trait AuthPlugin: Send{
    fn get_name(&self) -> String;
    fn get_login_page(&self, path: &String) -> String;
    fn get_actix_scope(&self) -> actix_web::Scope;
    fn as_any(&self) -> &dyn std::any::Any;
}
pub type PluginContainer = std::sync::Arc<std::sync::Mutex<dyn AuthPlugin>>;

pub fn get_plugin_data<T: 'static + Clone>(
    app_data: &crate::AppData,
    plugin_name: &str,
) -> Result<T, HttpResponse> {
    let mutex = match app_data.plugins.get(plugin_name) {
        Some(value) => value,
        None => {
            log::error!("failed to get plugin data for {}", plugin_name);
            return Err(err_internal());
        }
    };

    let mutex_guard = match mutex.lock() {
        Ok(guard) => guard,
        Err(err) => {
            log::error!("failed to lock plugin data for {}: {}", plugin_name, err);
            return Err(err_internal());
        }
    };

    let plugin = match mutex_guard.as_any().downcast_ref::<T>() {
        Some(value) => value,
        None => {
            log::error!("failed to cast plugin data for {} to {}", plugin_name, std::any::type_name::<T>());
            return Err(err_internal());
        }
    };

    Ok(plugin.clone())
}

pub fn flag(args: &Vec<String>, name: &str, default_enabled: bool) -> bool {
    (default_enabled || args.contains(&format!("--auth_{}", name).to_string())) && !args.contains(&format!("--no-auth_{}", name).to_string())
}
