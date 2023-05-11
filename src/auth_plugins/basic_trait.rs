
pub trait AuthPlugin: Send{
    fn get_name(&self) -> String;
    fn get_actix_scope(&self) -> actix_web::Scope;
    fn as_any(&self) -> &dyn std::any::Any;
}
pub type PluginContainer = std::sync::Arc<std::sync::Mutex<dyn AuthPlugin>>;

pub fn get_plugin_data<T: 'static + Clone>(
    app_data: &crate::AppData,
    plugin_name: &str,
) -> Result<T, ()> {
    let mutex = match app_data.plugins.get(plugin_name) {
        Some(value) => value,
        None => {
            log::error!("failed to get {} plugin data", plugin_name);
            return Err(());
        }
    };

    let mutex_guard = match mutex.lock() {
        Ok(guard) => guard,
        Err(_) => {
            log::error!("failed to lock {} plugin data", plugin_name);
            return Err(());
        }
    };

    let plugin = match mutex_guard.as_any().downcast_ref::<T>() {
        Some(value) => value,
        None => {
            log::error!("failed to cast {} to {}", plugin_name, std::any::type_name::<T>());
            return Err(());
        }
    };

    Ok(plugin.clone())
}
