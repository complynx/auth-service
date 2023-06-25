use std::{error::Error, collections::HashMap};
use rusqlite::{params, Result};
use serde::{Serialize, Deserialize};
use tokio_rusqlite::Connection;

#[derive(Debug, Clone)]
pub struct Database {
    conn: Connection,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct User {
    #[serde(skip_serializing)]
    db: Database,

    pub id: i64,
    pub roles: std::collections::HashSet<String>,
}

fn prepare_database(conn: &rusqlite::Connection) -> Result<()> {
    {// create tables
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT
            )",
            params![],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS user_oauth (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                issuer TEXT NOT NULL,
                outer_id TEXT NOT NULL,
                data BLOB,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(issuer, outer_id)
            )",
            params![],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                UNIQUE(name)
            )",
            params![],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                UNIQUE(name)
            )",
            params![],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS user_roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user INTEGER NOT NULL,
                role INTEGER NOT NULL,
                shareable INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user) REFERENCES users (id),
                FOREIGN KEY (role) REFERENCES roles (id),
                UNIQUE(user, role)
            )",
            params![],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS role_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role INTEGER NOT NULL,
                permission INTEGER NOT NULL,
                FOREIGN KEY (permission) REFERENCES permissions (id),
                FOREIGN KEY (role) REFERENCES roles (id),
                UNIQUE(permission, role)
            )",
            params![],
        )?;
        log::debug!("tables ok");
    }

    {// create default roles
        let roles = HashMap::from([
            ("su", "Super User — this will open any doors"),
            ("guest", "Basic role for everyone"),
        ]);
        for (role, desc) in roles {
            let count: i32 = conn.query_row(
                "SELECT COUNT(*) FROM roles WHERE name = ?1",
                params![role],
                |row| row.get(0),
            )?;

            if count == 0 {
                conn.execute(
                    "INSERT INTO roles (name, description) VALUES (?1, ?2)",
                    params![role, desc],
                )?;
            }
        }
        log::debug!("roles ok");
    }

    {// create admin permissions
        let permissions = HashMap::from([
            (crate::admin::PERMISSION_VIEW_USERS, ""),
            (crate::admin::PERMISSION_MANAGE_USERS, ""),
            (crate::admin::PERMISSION_VIEW_USER_ROLES, ""),
            (crate::admin::PERMISSION_MANAGE_USER_ROLES, ""),
            (crate::admin::PERMISSION_VIEW_ROLES, ""),
            (crate::admin::PERMISSION_MANAGE_ROLES, ""),
            (crate::admin::PERMISSION_CREATE_ROLES, ""),
            (crate::admin::PERMISSION_VIEW_ROLE_PERMISSIONS, ""),
            (crate::admin::PERMISSION_MANAGE_ROLE_PERMISSIONS, ""),
            (crate::admin::PERMISSION_VIEW_PERMISSIONS, ""),
            (crate::admin::PERMISSION_MANAGE_PERMISSIONS, ""),
            (crate::admin::PERMISSION_CREATE_PERMISSIONS, ""),
        ]);

        for (name, desc) in permissions {
            let count: i32 = conn.query_row(
                "SELECT COUNT(*) FROM permissions WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )?;

            if count == 0 {
                conn.execute(
                    "INSERT INTO permissions (name, description) VALUES (?1, ?2)",
                    params![name, desc],
                )?;
            }
        }
        log::debug!("admin perms ok");
    }

    {// add su admin
        let has_su: i32 = conn.query_row(
            "
                SELECT
                    COUNT(*)
                FROM user_roles 
                INNER JOIN roles ON roles.id = user_roles.role 
                WHERE roles.name = 'su'
            ",
            params![],
            |row| row.get(0),
        )?;

        if has_su == 0 {
            let su_issuer = std::env::var("SU_OAUTH_ISSUER").ok();
            let su_id = std::env::var("SU_OAUTH_ID").ok();
            if let (Some(issuer), Some(outer_id)) = (su_issuer,su_id) {
                conn.execute(
                    "
                        INSERT INTO users DEFAULT VALUES
                    ",
                    params![]
                )?;
                let id = conn.last_insert_rowid();
                conn.execute("
                        INSERT INTO user_roles (user, role, shareable)
                        SELECT ?1, id, 1
                        FROM roles WHERE name = 'su'
                    ",
                    params![id]
                )?;
                conn.execute("
                        INSERT INTO user_oauth (user_id, issuer, outer_id)
                        VALUES (?1, ?2, ?3)
                    ",
                    params![id, issuer, outer_id]
                )?;
            }
        }
        log::debug!("su ok");
    }

    Ok(())
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDescription {
    pub id: i64,
    pub name: String,
    pub description: String,
}

impl std::fmt::Display for RoleDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Role(#{} {}, \"{}\")", self.id, self.name, self.description)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOuterDescription {
    pub id: i64,
    pub issuer: String,
    pub outer_id: String,
    pub data: serde_json::Value,
}

impl std::fmt::Display for UserOuterDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserOuter(#{} outer({}|{}): {})", self.id, self.issuer, self.outer_id, self.data)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionDescription {
    pub id: i64,
    pub name: String,
    pub description: String,
}

impl std::fmt::Display for PermissionDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Permission(#{} {}, \"{}\")", self.id, self.name, self.description)
    }
}

impl Database {
    pub async fn new() -> Result<Self, Box<dyn Error>> {
        #[cfg(feature="sqlcipher")]
        let secret = std::env::var("SQLITE_SECRET").ok();

        let path = std::env::var("SQLITE_PATH")?;
        let db_file = format!("{}/auth.db", path);

        let conn = Connection::open(db_file).await?;
        log::debug!("open ok");

        #[cfg(feature="sqlcipher")]
        if let Some(secret_str) = secret {
            let secret_str = secret_str.replace("'", "''");
            let sql_command = format!("PRAGMA KEY='{}'", secret_str);
            conn.call(move |conn| {
                conn.execute(&sql_command, params![])
            }).await?;
            log::debug!("pragma ok");
        }
        conn.call(|conn| {
            prepare_database(&conn)
        }).await?;
        
        Ok(Self{
            conn,
        })
    }

    pub async fn get_users(&self) -> Result<Vec<UserOuterDescription>, Box<dyn Error>> {
        #[derive(Clone)]
        struct UserOuterInterim {
            id: i64,
            issuer: String,
            outer_id: String,
            data: String,
        }
        let ret = self.conn.call(move |conn| {
            let mut query = conn.prepare("
                SELECT
                    user_id, issuer, outer_id, data
                FROM user_oauth
            ")?;
            let rows = query.query_map(
                params![],
                |row| Ok(UserOuterInterim{
                    id: row.get(0)?,
                    issuer: row.get(1)?,
                    outer_id: row.get(2)?,
                    data: row.get(3)?,
                })
            )?;
            let mut ret = Vec::new();
            for role in rows {
                ret.push(role?);
            }
            Ok(ret)
        }).await?;
        let result: Result<Vec<UserOuterDescription>, Box<dyn std::error::Error>> = ret
            .into_iter()
            .map(|interim| {
                let data: serde_json::Value = serde_json::from_str(&interim.data)?;
                Ok(UserOuterDescription {
                    id: interim.id,
                    issuer: interim.issuer,
                    outer_id: interim.outer_id,
                    data,
                })
            })
            .collect();
        result
    }

    pub async fn get_user(&self, id: i64) -> Result<UserOuterDescription, Box<dyn Error>> {
        #[derive(Clone)]
        struct UserOuterInterim {
            id: i64,
            issuer: String,
            outer_id: String,
            data: String,
        }
        let ret = self.conn.call(move |conn| {
            let row: UserOuterInterim = conn.query_row("
                SELECT
                    user_id, issuer, outer_id, data
                FROM user_oauth
                WHERE user_id = ?1
                ",
                params![id],
                |row| Ok(UserOuterInterim{
                    id: row.get(0)?,
                    issuer: row.get(1)?,
                    outer_id: row.get(2)?,
                    data: row.get(3)?,
                })
            )?;
            Ok(row)
        }).await?;
        let data: serde_json::Value = serde_json::from_str(&ret.data)?;
        Ok(UserOuterDescription {
            id: ret.id,
            issuer: ret.issuer,
            outer_id: ret.outer_id,
            data,
        })
    }

    pub async fn get_roles(&self) -> Result<Vec<RoleDescription>, Box<dyn Error>> {
        let ret = self.conn.call(move |conn| {
            let mut query = conn.prepare("
                SELECT
                    id, name, description
                FROM roles
            ")?;
            let rows = query.query_map(
                params![],
                |row| Ok(RoleDescription{
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                })
            )?;
            let mut ret = Vec::new();
            for role in rows {
                ret.push(role?);
            }
            Ok(ret)
        }).await?;
        Ok(ret)
    }

    pub async fn get_permissions(&self) -> Result<Vec<PermissionDescription>, Box<dyn Error>> {
        let ret = self.conn.call(move |conn| {
            let mut query = conn.prepare("
                SELECT
                    id, name, description
                FROM permissions
            ")?;
            let rows = query.query_map(
                params![],
                |row| Ok(PermissionDescription{
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                })
            )?;
            let mut ret = Vec::new();
            for role in rows {
                ret.push(role?);
            }
            Ok(ret)
        }).await?;
        Ok(ret)
    }

    pub async fn get_permission(&self, id: i64) -> Result<PermissionDescription, Box<dyn Error>> {
        let ret = self.conn.call(move |conn| {
            let ret = conn.query_row("
                SELECT
                    id, name, description
                FROM permissions
                WHERE id = ?1
                ",
                params![id],
                |row| Ok(PermissionDescription{
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                })
            )?;
            Ok(ret)
        }).await?;
        Ok(ret)
    }

    pub async fn update_permission(&self, changes: PermissionDescription) -> Result<(), Box<dyn Error>> {
        self.conn.call(move |conn| {
            conn.execute("
                UPDATE permissions
                SET
                    name = ?2, description = ?3
                WHERE id = ?1
                ",
                params![changes.id, changes.name, changes.description]
            )?;
            Ok(())
        }).await?;
        Ok(())
    }

    pub async fn create_permission(&self, data: PermissionDescription) -> Result<i64, Box<dyn Error>> {
        let ret = self.conn.call(move |conn| {
            conn.execute("
                INSERT INTO permissions (name, description)
                VALUES (?1, ?2)
                ",
                params![data.name, data.description]
            )?;
            Ok(conn.last_insert_rowid())
        }).await?;
        Ok(ret)
    }

    pub async fn get_role(&self, id: i64) -> Result<RoleDescription, Box<dyn Error>> {
        let ret = self.conn.call(move |conn| {
            let role = conn.query_row("
                SELECT
                    id, name, description
                FROM roles
                WHERE id = ?1
                ",
                params![id],
                |row| Ok(RoleDescription{
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                })
            )?;
            Ok(role)
        }).await?;
        Ok(ret)
    }

    pub async fn update_role(&self, new_info: RoleDescription) -> Result<(), Box<dyn Error>> {
        self.conn.call(move |conn| {
            conn.execute("
                UPDATE roles
                SET
                    name = ?2, description = ?3
                WHERE id = ?1
                ",
                params![new_info.id, new_info.name, new_info.description]
            )?;
            Ok(())
        }).await?;
        Ok(())
    }

    pub async fn create_role(&self, new_info: RoleDescription) -> Result<i64, Box<dyn Error>> {
        let new_id = self.conn.call(move |conn| {
            conn.execute("
                INSERT INTO roles (name, description) VALUES (?1, ?2)
                ",
                params![new_info.name, new_info.description]
            )?;
            Ok(conn.last_insert_rowid())
        }).await?;
        Ok(new_id)
    }

    pub async fn get_role_permissions(&self, id: i64) -> Result<Vec<PermissionDescription>, Box<dyn Error>> {
        let ret = self.conn.call(move |conn| {
            let mut query = conn.prepare("
                SELECT
                    permissions.id, permissions.name, permissions.description
                FROM permissions
                INNER JOIN role_permissions ON permissions.id = role_permissions.permission
                WHERE role_permissions.role = ?1
            ")?;
            let rows = query.query_map(
                params![id],
                |row| Ok(PermissionDescription{
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                })
            )?;
            let mut ret = Vec::new();
            for role in rows {
                ret.push(role?);
            }
            Ok(ret)
        }).await?;
        Ok(ret)
    }

    pub async fn add_role_permissions(&self, role_id: i64, permission_ids: Vec<i64>) -> Result<(), Box<dyn Error>> {
        self.conn.call(move |conn| {
            let batch_size = 1000;
            for chunk in permission_ids.chunks(batch_size) {
                let mut query = String::from("INSERT OR IGNORE INTO role_permissions (role, permission) VALUES ");
                let mut values = Vec::new();

                for (i, &perm) in chunk.iter().enumerate() {
                    if i != 0 {
                        query.push_str(", ");
                    }
                    query.push_str(&format!("(?{}, ?{})", 2*i+1, 2*i+2));
                    values.push(role_id);
                    values.push(perm);
                }

                conn.execute(&query, rusqlite::params_from_iter(values))?;
            }
            Ok(())
        }).await?;
        Ok(())
    }

    pub async fn remove_role_permissions(&self, role_id: i64, permission_ids: Vec<i64>) -> Result<(), Box<dyn Error>> {
        self.conn.call(move |conn| {
            let batch_size = 1000;
            for chunk in permission_ids.chunks(batch_size) {
                let mut query = String::from("DELETE FROM role_permissions WHERE role = ?1 AND permission IN (");
                let mut values = Vec::new();

                values.push(role_id);

                for (i, &perm) in chunk.iter().enumerate() {
                    if i != 0 {
                        query.push_str(", ");
                    }
                    query.push_str(&format!("?{}", i + 2));
                    values.push(perm);
                }

                query.push_str(")");

                conn.execute(&query, rusqlite::params_from_iter(values))?;
            }
            Ok(())
        }).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct UserInternal {
    id: i64,
}

#[derive(Debug, Clone)]
struct RoleInternal {
    name: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRoleDescription {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub shareable: bool,
}

pub fn is_not_found(err: &Box<dyn Error>) -> bool {
    match err.downcast_ref::<rusqlite::Error>() {
        Some(rusqlite::Error::QueryReturnedNoRows) => true,
        _ => false
    }
}

async fn get_user_roles(db: Database, id: i64) -> Result<std::collections::HashSet<String>, tokio_rusqlite::Error> {
    db.conn.call(move |conn| {
        let mut query = conn.prepare("
            SELECT
                roles.name 
            FROM roles 
            INNER JOIN user_roles ON roles.id = user_roles.role 
            WHERE user_roles.user = ?1
        ")?;
        let rows = query.query_map(
            params![id],
            |row| Ok(RoleInternal{
                name: row.get(0)?
            })
        )?;
        let mut ret = Vec::new();
        for role in rows {
            ret.push(role?.name);
        }
        if ret.len() == 0 {
            ret.push("guest".to_string());
        }
        Ok(ret.into_iter().collect())
    }).await
}

impl User {
    pub async fn get_by_id(db: Database, id: i64) -> Result<Self, Box<dyn Error>> {
        let user_internal = db.conn.call(move |conn| {
            let u_internal = conn.query_row(
                "SELECT id FROM users WHERE id = ?1",
                params![id],
                |row| Ok(UserInternal{
                    id: row.get(0)?
                })
            )?;
            Ok(u_internal)
        }).await?;

        Ok(User {
            db: db.clone(),
            id: user_internal.id,
            roles: get_user_roles(db, user_internal.id).await?,
        })
    }

    pub async fn get_by_outer_id(db: Database, issuer: String, outer_id: String) -> Result<Self, Box<dyn Error>> {
        let user_internal = db.conn.call(move |conn| {
            let u_internal = conn.query_row(
                "
                    SELECT
                        users.id 
                    FROM users
                    INNER JOIN user_oauth ON users.id = user_oauth.user_id 
                    WHERE user_oauth.issuer = ?1 AND user_oauth.outer_id = ?2
                ",
                params![issuer,outer_id],
                |row| Ok(UserInternal{
                    id: row.get(0)?
                })
            )?;
            Ok(u_internal)
        }).await?;

        Ok(User {
            db: db.clone(),

            id: user_internal.id,
            roles: get_user_roles(db, user_internal.id).await?,
        })
    }

    pub async fn update_oauth_data(&self, data: serde_json::Value) -> Result<(), Box<dyn Error>> {
        let data_str = data.to_string();
        let inner_id = self.id.clone();
        self.db.conn.call(move |conn| {
            conn.execute(
                "
                    UPDATE
                        user_oauth 
                    SET
                        data = ?2
                    WHERE
                        user_id = ?1
                ",
                params![inner_id, data_str]
            )
        }).await?;

        Ok(())
    }

    pub async fn get_manageable_roles(&self) -> Result<std::collections::HashSet<String>, Box<dyn Error>> {
        let inner_id = self.id.clone();
        let ret = self.db.conn.call(move |conn| {

            let mut query = conn.prepare("
                SELECT roles.name
                FROM user_roles
                INNER JOIN roles ON user_roles.role = roles.id
                WHERE user_roles.user = ?1 AND user_roles.shareable = 1
            ")?;
            let rows = query.query_map(
                params![inner_id],
                |row| Ok(row.get(0)?)
            )?;
            let mut ret = Vec::new();
            for role in rows {
                ret.push(role?);
            }
            Ok(ret)
        }).await?;
        Ok(ret.into_iter().collect())
    }

    pub async fn get_roles_full(&self) -> Result<Vec<UserRoleDescription>, Box<dyn Error>> {
        let inner_id = self.id.clone();
        let roles = self.db.conn.call(move |conn| {
            let mut query = conn.prepare("
                SELECT
                    roles.id, roles.name, roles.description, user_roles.shareable
                FROM roles 
                INNER JOIN user_roles ON roles.id = user_roles.role 
                WHERE user_roles.user = ?1
            ")?;
            let rows = query.query_map(
                params![inner_id],
                |row| Ok(UserRoleDescription{
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    shareable: row.get(3)?,
                })
            )?;
            let mut ret = Vec::new();
            for role in rows {
                ret.push(role?);
            }
            Ok(ret)
        }).await?;

        Ok(roles)
    }

    pub async fn remove_role(&mut self, role_name: String) -> Result<(), Box<dyn Error>> {
        if !self.roles.contains(&role_name) {
            return Ok(());
        }
        let inner_id = self.id.clone();
        let role_name_borrow = role_name.clone();
        self.db.conn.call(move |conn| {
            conn.execute("
                DELETE FROM user_roles
                WHERE user_roles.user = ?1 AND user_roles.role IN (
                    SELECT roles.id
                    FROM roles
                    WHERE roles.name = ?2
                )
                ",
                params![inner_id, role_name_borrow]
            )
        }).await?;
        self.roles.remove(&role_name);
        Ok(())
    }

    pub async fn add_role(&mut self, role_name: String, shareable: bool) -> Result<(), Box<dyn Error>> {
        let inner_id = self.id.clone();
        let has_role = self.roles.contains(&role_name);
        let role_name_borrow = role_name.clone();
        self.db.conn.call(move |conn| {
            conn.execute(
                if has_role {
                    "
                    UPDATE user_roles
                    SET shareable = ?3
                    WHERE user = ?1
                        AND role IN (
                            SELECT id
                            FROM roles
                            WHERE name = ?2
                        )
                    "
                } else {
                    "
                    INSERT INTO user_roles (user, role, shareable)
                    SELECT ?1, roles.id, ?3
                    FROM roles
                    WHERE roles.name = ?2
                    "
                },
                params![inner_id, &role_name_borrow, if shareable { 1 } else { 0 }]
            )
        }).await?;
        self.roles.insert(role_name);
        Ok(())
    }

    pub async fn get_permissions(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let inner_id = self.id.clone();
        let ret = self.db.conn.call(move |conn| {

            let mut query = conn.prepare("
                SELECT permissions.name
                FROM user_roles
                INNER JOIN role_permissions ON user_roles.role = role_permissions.role
                INNER JOIN permissions ON role_permissions.permission = permissions.id
                WHERE user_roles.user = ?1
            ")?;
            let rows = query.query_map(
                params![inner_id],
                |row| Ok(row.get(0)?)
            )?;
            let mut ret = Vec::new();
            for permission in rows {
                ret.push(permission?);
            }
            Ok(ret)
        }).await?;
        Ok(ret)
    }

    pub async fn has_permission(&self, permission: String) -> Result<bool, Box<dyn Error>> {
        if self.is_su() {
            return Ok(true);
        }
        let inner_id = self.id.clone();
        let ret = self.db.conn.call(move |conn| {
            let count: i64 = conn.query_row("
                    SELECT count(*)
                    FROM user_roles
                    INNER JOIN role_permissions ON user_roles.role = role_permissions.role
                    INNER JOIN permissions ON role_permissions.permission = permissions.id
                    WHERE user_roles.user = ?1 AND permissions.name = ?2
                ",
                params![inner_id, permission],
                |row| Ok(row.get(0)?)
            )?;
            Ok(count>0)
        }).await?;
        Ok(ret)
    }

    pub fn is_su(&self) -> bool {
        self.roles.contains("su")
    }

    // pub async fn create_new_guest(db: Database) -> Result<Self, Box<dyn Error>> {
    //     let id = db.conn.call(move |conn| {
    //         let tx = conn.transaction()?;
    //         tx.execute(
    //             "
    //                 INSERT INTO users DEFAULT VALUES
    //             ",
    //             params![]
    //         )?;
    //         let id = tx.last_insert_rowid();
    //         tx.execute("
    //                 INSERT INTO user_roles (user, role)
    //                 SELECT ?1, id
    //                 FROM roles WHERE name = 'guest'
    //             ",
    //             params![id]
    //         )?;
    //         tx.commit()?;
    //         Ok(id)
    //     }).await?;
    //     Ok(User::get_by_id(db, id).await?)
    // }

    pub async fn create_new_guest_oauth(db: Database, issuer: String, outer_id: String) -> Result<Self, Box<dyn Error>> {
        let id = db.conn.call(move |conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "
                    INSERT INTO users DEFAULT VALUES
                ",
                params![]
            )?;
            let id = tx.last_insert_rowid();
            tx.execute("
                    INSERT INTO user_roles (user, role)
                    SELECT ?1, id
                    FROM roles WHERE name = 'guest'
                ",
                params![id]
            )?;
            tx.execute("
                    INSERT INTO user_oauth (user_id, issuer, outer_id)
                    VALUES (?1, ?2, ?3)
                ",
                params![id, issuer, outer_id]
            )?;
            tx.commit()?;
            Ok(id)
        }).await?;

        Ok(User::get_by_id(db, id).await?)
    }
}

impl std::fmt::Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "User({})", self.id)
    }
}
