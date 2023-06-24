use actix_web::{web, get, HttpResponse, HttpRequest, Responder, post, put};
use serde::Deserialize;
use serde_json::json;

use crate::{AppData, U, check_session, database::{User, is_not_found}, AuthToken, err_internal, ErrorResponse};

pub(crate) const PERMISSION_VIEW_USERS: &str = "view_users";
pub(crate) const PERMISSION_MANAGE_USERS: &str = "manage_users";
pub(crate) const PERMISSION_VIEW_USER_ROLES: &str = "view_user_roles";
pub(crate) const PERMISSION_MANAGE_USER_ROLES: &str = "manage_user_roles";
pub(crate) const PERMISSION_VIEW_ROLES: &str = "view_roles";
pub(crate) const PERMISSION_MANAGE_ROLES: &str = "manage_roles";
pub(crate) const PERMISSION_CREATE_ROLES: &str = "create_roles";
pub(crate) const PERMISSION_VIEW_ROLE_PERMISSIONS: &str = "view_role_permissions";
pub(crate) const PERMISSION_MANAGE_ROLE_PERMISSIONS: &str = "manage_role_permissions";
pub(crate) const PERMISSION_VIEW_PERMISSIONS: &str = "view_permissions";
pub(crate) const PERMISSION_MANAGE_PERMISSIONS: &str = "manage_permissions";
pub(crate) const PERMISSION_CREATE_PERMISSIONS: &str = "create_permissions";

pub(crate) const MAX_PERMISSION_LENGTH: usize = 30;

pub(crate) async fn get_current_user(app_data: &AppData, token: &AuthToken) -> Result<User, HttpResponse> {
    match token.sub.parse() {
        Ok(id) => User::get_by_id(app_data.database.clone(), id).await.map_err(|err| {
            log::debug!("failed to retrieve User from token: {}", err);
            err_internal()
        }),
        Err(err) => {
            log::debug!("failed to parse token.sub: {}", err);
            Err(err_internal())
        }
    }
}

pub(crate) async fn permit(user: &User, permission: &str) -> Result<(), HttpResponse> {
    match user.has_permission(permission.to_string()).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(HttpResponse::Forbidden().json(ErrorResponse{error: "insufficient permissions".to_string()})),
        Err(err) => {
            log::error!("failed to check user permission: {}", err);
            Err(err_internal())
        }
    }
}

#[allow(dead_code)]
const ROLE_SET: i32 = 1;
const ROLE_SHAREABLE: i32 = 2;
const ROLE_UNSET: i32 = 0;

#[derive(Clone, Debug, Deserialize, Default)]
struct UserRoleChangeData{
    name: String,
    action: i32,
}

#[derive(Clone, Debug, Deserialize, Default)]
struct UserRolesChange {
    roles: Vec<UserRoleChangeData>
}

#[derive(Clone, Debug, Deserialize, Default)]
struct RolePermissionsChange {
    add: Vec<i64>,
    remove: Vec<i64>,
}

#[get("/roles")]
async fn get_roles(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);
    U!(permit(&current_user, PERMISSION_VIEW_ROLES).await);

    let roles = U!(app_data.as_ref().database.get_roles().await.map_err(|err| {
        log::error!("failed to fetch roles: {}", err);
        err_internal()
    }));

    HttpResponse::Ok().json(
        json!({
            "roles": roles
        })
    )
}

#[get("/role/{id}")]
async fn get_role(
    id: web::Path<i64>,
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);
    U!(permit(&current_user, PERMISSION_VIEW_ROLES).await);

    let role = U!(app_data.as_ref().database.get_role(*id).await.map_err(|err| if is_not_found(&err) {
        HttpResponse::NotFound().json(ErrorResponse{error:"role not found".to_string()})
    } else {
        log::error!("failed to fetch role: {}", err);
        err_internal()
    }));

    HttpResponse::Ok().json(role)
}

#[post("/role/{id}")]
async fn edit_role(
    id: web::Path<i64>,
    req: HttpRequest,
    app_data: web::Data<AppData>,
    role_change: web::Json<crate::database::RoleDescription>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);
    U!(permit(&current_user, PERMISSION_MANAGE_ROLES).await);

    if *id != role_change.id {
        log::error!("id mismatch");
        return HttpResponse::BadRequest().json(ErrorResponse{error:"id mismatch".to_string()});
    }

    let role_old = U!(app_data.as_ref().database.get_role(*id).await.map_err(|err| if is_not_found(&err) {
        HttpResponse::NotFound().json(ErrorResponse{error:"role not found".to_string()})
    } else {
        log::error!("failed to fetch role: {}", err);
        err_internal()
    }));

    log::info!("role edit. {}, Old: {}, Changes: {}", current_user, role_old, role_change);

    U!(app_data.as_ref().database.update_role(role_change.clone()).await.map_err(|err| {
        log::error!("failed to change role: {}", err);
        err_internal()
    }));

    let role = U!(app_data.as_ref().database.get_role(*id).await.map_err(|err| if is_not_found(&err) {
        HttpResponse::NotFound().json(ErrorResponse{error:"role not found".to_string()})
    } else {
        log::error!("failed to fetch role: {}", err);
        err_internal()
    }));

    HttpResponse::Ok().json(role)
}

#[put("/role")]
async fn create_role(
    req: HttpRequest,
    app_data: web::Data<AppData>,
    new_role: web::Json<crate::database::RoleDescription>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);
    U!(permit(&current_user, PERMISSION_CREATE_ROLES).await);

    let id = U!(app_data.as_ref().database.create_role(new_role.clone()).await.map_err(|err| {
        log::error!("failed to create role: {}", err);
        err_internal()
    }));

    let role = U!(app_data.as_ref().database.get_role(id).await.map_err(|err| if is_not_found(&err) {
        HttpResponse::NotFound().json(ErrorResponse{error:"role not found".to_string()})
    } else {
        log::error!("failed to fetch role: {}", err);
        err_internal()
    }));
    
    log::info!("role creation. {}, {}", current_user, role);

    HttpResponse::Ok().json(role)
}

#[get("/role/{id}/permissions")]
async fn get_role_permissions(
    id: web::Path<i64>,
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);
    U!(permit(&current_user, PERMISSION_VIEW_ROLE_PERMISSIONS).await);

    let role = U!(app_data.as_ref().database.get_role(*id).await.map_err(|err| if is_not_found(&err) {
        HttpResponse::NotFound().json(ErrorResponse{error:"role not found".to_string()})
    } else {
        log::error!("failed to fetch role: {}", err);
        err_internal()
    }));

    let perms = U!(app_data.as_ref().database.get_role_permissions(*id).await.map_err(|err| {
        log::error!("failed to fetch role permissions: {}", err);
        err_internal()
    }));

    HttpResponse::Ok().json(
        json!({
            "role": role,
            "permissions": perms,
        })
    )
}

#[post("/role/{id}/permissions")]
async fn change_role_permissions(
    id: web::Path<i64>,
    req: HttpRequest,
    app_data: web::Data<AppData>,
    permissions_change: web::Json<RolePermissionsChange>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);
    U!(permit(&current_user, PERMISSION_MANAGE_ROLE_PERMISSIONS).await);

    let role = U!(app_data.as_ref().database.get_role(*id).await.map_err(|err| if is_not_found(&err) {
        HttpResponse::NotFound().json(ErrorResponse{error:"role not found".to_string()})
    } else {
        log::error!("failed to fetch role: {}", err);
        err_internal()
    }));

    log::info!("role permissions change. {}, {}, Changes: {:?}", current_user, role, permissions_change);

    U!(app_data.as_ref().database.add_role_permissions(role.id, permissions_change.add.clone()).await.map_err(|err| {
        log::error!("failed to add role permissions: {}", err);
        err_internal()
    }));

    U!(app_data.as_ref().database.remove_role_permissions(role.id, permissions_change.remove.clone()).await.map_err(|err| {
        log::error!("failed to remove role permissions: {}", err);
        err_internal()
    }));

    let perms = U!(app_data.as_ref().database.get_role_permissions(*id).await.map_err(|err| {
        log::error!("failed to fetch role permissions: {}", err);
        err_internal()
    }));

    HttpResponse::Ok().json(
        json!({
            "role": role,
            "permissions": perms,
        })
    )
}

#[get("/permissions")]
async fn get_permissions(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);
    U!(permit(&current_user, PERMISSION_VIEW_PERMISSIONS).await);

    let permissions = U!(app_data.as_ref().database.get_permissions().await.map_err(|err| {
        log::error!("failed to fetch permissions: {}", err);
        err_internal()
    }));

    HttpResponse::Ok().json(
        json!({
            "permissions": permissions
        })
    )
}

#[get("/permission/{id}")]
async fn get_permission(
    id: web::Path<i64>,
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);
    U!(permit(&current_user, PERMISSION_VIEW_PERMISSIONS).await);

    let permission = U!(app_data.as_ref().database.get_permission(id.clone()).await.map_err(|err|
    if is_not_found(&err) {
        HttpResponse::NotFound().json(ErrorResponse{error:"permission not found".to_string()})
    } else {
        log::error!("failed to fetch permission: {}", err);
        err_internal()
    }));

    HttpResponse::Ok().json(permission)
}

#[post("/permission/{id}")]
async fn edit_permission(
    id: web::Path<i64>,
    req: HttpRequest,
    app_data: web::Data<AppData>,
    changes: web::Json<crate::database::PermissionDescription>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);
    U!(permit(&current_user, PERMISSION_MANAGE_PERMISSIONS).await);

    if *id != changes.id {
        log::error!("id mismatch");
        return HttpResponse::BadRequest().json(ErrorResponse{error:"id mismatch".to_string()});
    }

    let old_permission = U!(app_data.as_ref().database.get_permission(id.clone()).await.map_err(|err|
    if is_not_found(&err) {
        HttpResponse::NotFound().json(ErrorResponse{error:"permission not found".to_string()})
    } else {
        log::error!("failed to fetch permission: {}", err);
        err_internal()
    }));

    log::info!("permission edit. {}, Old: {}, Changes: {}", current_user, old_permission, changes);

    U!(app_data.as_ref().database.update_permission(changes.clone()).await.map_err(|err|{
        log::error!("failed to update permission: {}", err);
        err_internal()
    }));

    let permission = U!(app_data.as_ref().database.get_permission(id.clone()).await.map_err(|err|
    if is_not_found(&err) {
        HttpResponse::NotFound().json(ErrorResponse{error:"permission not found".to_string()})
    } else {
        log::error!("failed to fetch permission: {}", err);
        err_internal()
    }));

    HttpResponse::Ok().json(permission)
}

#[put("/permission")]
async fn create_permission(
    req: HttpRequest,
    app_data: web::Data<AppData>,
    permission: web::Json<crate::database::PermissionDescription>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);
    U!(permit(&current_user, PERMISSION_CREATE_PERMISSIONS).await);

    let id = U!(app_data.as_ref().database.create_permission(permission.clone()).await.map_err(|err| {
        log::error!("failed to create permission: {}", err);
        err_internal()
    }));

    let permission = U!(app_data.as_ref().database.get_permission(id).await.map_err(|err|
    if is_not_found(&err) {
        HttpResponse::NotFound().json(ErrorResponse{error:"permission not found".to_string()})
    } else {
        log::error!("failed to fetch permission: {}", err);
        err_internal()
    }));

    log::info!("permission create. {}, {}", current_user, permission);

    HttpResponse::Ok().json(permission)
}

#[get("/users")]
async fn get_users(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);
    U!(permit(&current_user, PERMISSION_VIEW_USERS).await);

    let users =  U!(app_data.as_ref().database.get_users().await.map_err(|err| {
        log::error!("failed to fetch permission: {}", err);
        err_internal()
    }));

    HttpResponse::Ok().json(json!({
        "users": users
    }))
}

#[get("/self")]
async fn get_self(
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);

    let user =  U!(app_data.as_ref().database.get_user(current_user.id).await.map_err(|err| {
        log::error!("failed to fetch self: {}", err);
        err_internal()
    }));

    HttpResponse::Ok().json(json!({
        "self": user
    }))
}

#[post("/user/{id}/roles")]
async fn change_user_roles(
    id: web::Path<i64>,
    req: HttpRequest,
    app_data: web::Data<AppData>,
    roles: web::Json<UserRolesChange>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);

    if *id.as_ref() != current_user.id {
        U!(permit(&current_user, PERMISSION_MANAGE_USER_ROLES).await);
    }

    let mut user = U!(User::get_by_id(app_data.database.clone(), *id).await.map_err(|err| if is_not_found(&err) {
        HttpResponse::NotFound().json(ErrorResponse{error:"user not found".to_string()})
    } else {
        log::error!("failed to fetch user: {}", err);
        err_internal()
    }));

    let manageable_roles = U!(current_user.get_manageable_roles().await.map_err(|err| {
        log::error!("failed to fetch manageable roles: {}", err);
        err_internal()
    }));

    if current_user.is_su() {
        if !manageable_roles.contains("su") {
            // non-shareable su can change and share any roles except itself
            for role in &roles.roles {
                if role.name == "su" {
                    return HttpResponse::Forbidden().json(ErrorResponse{error:"attempt to change unmanageable role".to_string()})
                }
            }
        }
    } else {
        for role in &roles.roles {
            if !manageable_roles.contains(&role.name) {
                return HttpResponse::Forbidden().json(ErrorResponse{error:"attempt to change unmanageable role".to_string()})
            }
        }
    }

    log::info!("user roles change. Editor: {}, Editing: {}, Changes: {:?}", current_user, user, roles.roles);

    for role in &roles.roles {
        if role.action == ROLE_UNSET {
            U!(user.remove_role(role.name.clone()).await.map_err(|err| {
                log::error!("failed to delete role: {}", err);
                err_internal()
            }));
        } else {
            U!(user.add_role(role.name.clone(), role.action & ROLE_SHAREABLE > 0).await.map_err(|err| {
                log::error!("failed to add role: {}", err);
                err_internal()
            }));
        }
    }

    let roles = U!(user.get_roles_full().await.map_err(|err| {
        log::error!("failed to fetch roles: {}", err);
        err_internal()
    }));

    HttpResponse::Ok().json(
        json!({
            "roles": roles
        })
    )
}

#[get("/user/{id}/roles")]
async fn user_roles(
    id: web::Path<i64>,
    req: HttpRequest,
    app_data: web::Data<AppData>,
) -> impl Responder {
    log::debug!("request: {:?}", req);
    let token = U!(check_session(req, app_data.clone()).await);
    let current_user = U!(get_current_user(&app_data, &token).await);
    let mut id_fix = *id;
    
    if id_fix < 0 {
        id_fix = current_user.id;
    }

    if id_fix != current_user.id {
        U!(permit(&current_user, PERMISSION_VIEW_USER_ROLES).await);
    }
    let user = U!(User::get_by_id(app_data.database.clone(), id_fix).await.map_err(|err| if is_not_found(&err) {
        HttpResponse::NotFound().json(ErrorResponse{error:"user not found".to_string()})
    } else {
        log::error!("failed to fetch user: {}", err);
        err_internal()
    }));

    let roles = U!(user.get_roles_full().await.map_err(|err| {
        log::error!("failed to fetch roles: {}", err);
        err_internal()
    }));

    HttpResponse::Ok().json(
        json!({
            "roles": roles
        })
    )
}

pub fn init() -> actix_web::Scope {
    actix_web::Scope::new("/adm")
        .service(get_self)
        .service(get_users)
        .service(user_roles)
        .service(change_user_roles)
        .service(get_roles)
        .service(get_role)
        .service(edit_role)
        .service(create_role)
        .service(get_role_permissions)
        .service(change_role_permissions)
        .service(get_permissions)
        .service(get_permission)
        .service(edit_permission)
        .service(create_permission)
}
