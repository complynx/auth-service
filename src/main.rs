use actix_web::{get, post, web, App, HttpServer, Responder, HttpResponse, HttpRequest};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;
use actix_web::middleware::Logger;
use env_logger::Env;
use tokio::time::interval;
use clap::Parser;

#[derive(Serialize, Debug)]
struct LoginResponse {
    session_id: String,
}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    error: &'static str,
}

#[derive(Deserialize, Debug)]
struct LoginForm {
    username: String,
    password: String
}

type SessionStore = Arc<Mutex<HashMap<String, (String, Instant)>>>;

#[post("/auth/login")]
async fn login(
    web::Form(data): web::Form<LoginForm>,
    session_store: web::Data<SessionStore>,
) -> impl Responder {

    if data.username == "test" && data.password == "password" {
        let session_id = Uuid::new_v4().to_string();
        let mut store = session_store.lock().unwrap();
        store.insert(
            session_id.clone(),
            (data.username.clone(), Instant::now() + Duration::from_secs(3600)),
        );
        HttpResponse::Ok().json(LoginResponse { session_id })
    } else {
        HttpResponse::Unauthorized().json(ErrorResponse { error: "Invalid credentials" })
    }
}

#[get("/auth/check")]
async fn check_session(
    req: HttpRequest,
    session_store: web::Data<SessionStore>,
) -> impl Responder {
    let session_id = match req.headers().get("X-Session-Id") {
        Some(value) => match value.to_str() {
            Ok(value) => value.to_string(),
            Err(_) => return HttpResponse::BadRequest().body("Invalid X-Session-Id header"),
        },
        None => return HttpResponse::BadRequest().body("Missing X-Session-Id header"),
    };
    let mut store = session_store.lock().unwrap();
    if let Some((username, expiration)) = store.get_mut(&session_id) {
        if *expiration > Instant::now() {
            *expiration = Instant::now() + Duration::from_secs(3600);
            HttpResponse::Ok().append_header(("X-Authenticated-User", username.clone())).finish()
        } else {
            store.remove(&session_id);
            HttpResponse::Unauthorized().json(ErrorResponse { error: "Expired session" })
        }
    } else {
        HttpResponse::Unauthorized().json(ErrorResponse { error: "Invalid session" })
    }
}

async fn clean_expired_sessions(session_store: SessionStore) {
    let mut interval = interval(Duration::from_secs(600));
    loop {
        interval.tick().await;
        let mut store = session_store.lock().unwrap();
        store.retain(|_, (_, expiration)| *expiration > Instant::now());
    }
}


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {

    /// Server binds to this port
    #[arg(short, long, default_value_t = 8080)]
    port: u16,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let session_store: SessionStore = Arc::new(Mutex::new(HashMap::new()));
    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    let cleaner_session_store = session_store.clone();
    tokio::spawn(async move {
        clean_expired_sessions(cleaner_session_store).await;
    });

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
            .app_data(web::Data::new(session_store.clone()))
            .service(check_session)
            .service(login)
    })
    .bind(("0.0.0.0", args.port))?
    .bind(("::", args.port))?
    .run()
    .await
}
