pub mod example_auth;
pub mod google_auth;
pub mod basic_trait;


#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user: String,
    pub issuer: String,
}
