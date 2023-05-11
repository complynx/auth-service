use std::env;

use actix_web::HttpRequest;
use log::debug;


pub fn env_var(key: &str) -> Result<String, std::io::Error> {
    match env::var(key) {
        Ok(s) => {
            if s == "" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Environment variable {} is empty.", key)
                ));
            } else {
                return Ok(s);
            }
        },
        Err(err) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Missing the {} environment variable: {}", key, err)
        ))
    }
}

#[macro_export]
macro_rules! U {
    ($expr:expr) => {
        match $expr {
            Ok(value) => value,
            Err(err) => return err,
        }
    };
}


pub fn get_header_string(req: &HttpRequest, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    fn parse(req: &HttpRequest, key: &str) -> Result<String, Box<dyn std::error::Error>> {
        let ret = req.headers()
            .get(key)
            .ok_or(format!("Header {} not found", key))?
            .to_str()?;
        Ok(ret.to_string())
    }
    match parse(req, key) {
        Ok(s) => {
            debug!("got header {}: {}", key, s);
            Ok(s)
        },
        Err(e) => {
            debug!("failed to get header {}: {}", key, e);
            Err(e)
        }
    }
}

pub fn remove_path_last_part(url_path: String) -> String {
    let mut parts = url_path.split('/').collect::<Vec<&str>>();
    if !parts.is_empty() {
        parts.pop();
    }
    parts.join("/")
}
