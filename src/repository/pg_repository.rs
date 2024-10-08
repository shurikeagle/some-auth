use chrono::{DateTime, Utc};
use std::fmt;

use axum::async_trait;
use tokio_postgres::NoTls;

use crate::{user_service::Role, AuthUser};

use super::AuthRepository;

static SELECT_ALL_FROM_USERS: &str = "\
    SELECT
        id,
        username,
        pwd_hash,
        blocked,
        created_at,
        updated_at
    FROM users
";

static SELECT_ALL_FROM_ROLES: &str = "\
    SELECT 
        id,
        name,
        created_at,
        updated_at
    FROM roles
";

/// Postgres implemetation of [`AuthRepository`]
pub struct PgAuthRepository {
    conn_string: String
}

impl fmt::Debug for PgAuthRepository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PgAuthRepository")
    }
}

impl PgAuthRepository {
    /// Creates `[PgAuthRepository]`. Tries to connect on creation
    pub async fn create(conn_string: String) -> Result<Self, String> {
        if conn_string == "" {
            return Err("Connection string for PgAuthRepository must be non-empty".to_string());
        }

        if let Err(err) = tokio_postgres::connect(&conn_string, NoTls).await {
            return Err(format!("Connection error by provided connection string for PgAuthRepository: {}", err));
        }

        Ok(PgAuthRepository {
            conn_string
        })
    }
}

#[async_trait]
impl<TAuthUser: AuthUser + fmt::Debug + Send + Sync> AuthRepository<TAuthUser> for PgAuthRepository {
    async fn add_user(&self, user: &TAuthUser) -> Result<i32, String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        let created_res = client.query_one("\
            INSERT INTO users (username, pwd_hash, blocked, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id;",
            &[
                &user.username(),
                &user.pwd_hash(),
                &user.blocked(),
                &user.created_at(),
                &user.updated_at()
            ])
            .await
            .map_err(|err| err.to_string())?;

        Ok(created_res.get("id"))
    }

    async fn update_user(&self, user: &TAuthUser) -> Result<(), String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        let updated_rows = client.execute("\
            UPDATE users
            SET pwd_hash = $1,
                updated_at = $2
            WHERE id = $3;", &[
                &user.pwd_hash(),
                &user.updated_at(),
                &user.id()]).await.map_err(|err| err.to_string())?;
        if updated_rows == 0 {
            return Err(format!("Couldn't find user with id {} to update", user.id()));
        }

        Ok(())
    }

    async fn get_users(&self) -> Result<Vec<TAuthUser>, String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        Ok(client.query(
            SELECT_ALL_FROM_USERS, &[])
            .await
            .map_err(|err| err.to_string())?
            .iter()
            .map(|row| map_to_user(row))
            .collect())
    }

    async fn get_user(&self, id: i32) -> Result<Option<TAuthUser>, String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        let query = format!("\
            {SELECT_ALL_FROM_USERS}
            WHERE id=$1;");
        let row = client.query_opt(&query, &[&id])
            .await
            .map_err(|err| err.to_string())?;

        Ok(row.map(|row| map_to_user(&row)))
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<TAuthUser>, String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        let query = format!("\
            {SELECT_ALL_FROM_USERS}
            WHERE username=$1;");
        let row = client.query_opt(&query, &[&username])
            .await
            .map_err(|err| err.to_string())?;

        Ok(row.map(|row| map_to_user(&row)))
    }

    async fn update_user_refresh_token(&self, user_id: i32, token_hash: &str, time_updated: DateTime<Utc>) -> Result<(), String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        client.execute("\
            INSERT INTO refreshes (user_id, token_hash, time_updated)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id) DO UPDATE
                SET token_hash = $2,
                    time_updated = $3;",
            &[
                &user_id,
                &token_hash,
                &time_updated
            ])
            .await
            .map_err(|err| err.to_string())?;

        Ok(())
    }

    async fn get_user_refresh_token(&self, user_id: i32) -> Result<Option<String>, String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        let query = format!("\
            SELECT token_hash
            FROM refreshes
            WHERE user_id = $1;");
        let row = client.query_opt(&query, &[&user_id])
            .await
            .map_err(|err| err.to_string())?
            .map(|row| row.get("token_hash"));

        Ok(row)
    }

    async fn add_role(&self, role: &Role) -> Result<i32, String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        let created_res = client.query_one("\
            INSERT INTO roles (name, created_at, updated_at)
            VALUES ($1, $2, $3)
            RETURNING id;",
            &[
                &role.name(),
                &role.created_at(),
                &role.updated_at()
            ])
            .await
            .map_err(|err| err.to_string())?;

        Ok(created_res.get("id"))
    }

    async fn update_role(&self, role: &Role) -> Result<(), String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        let updated_rows = client.execute("\
            UPDATE roles
            SET name = $1,
                updated_at = $2
            WHERE id = $3;", &[
                &role.name(),
                &role.updated_at(),
                &role.id()]).await.map_err(|err| err.to_string())?;
        if updated_rows == 0 {
            return Err(format!("Couldn't find role with id {} to update", role.id()));
        }

        Ok(())
    }

    async fn update_user_roles(&self, user_id: i32, roles: &Vec<i32>) -> Result<(), String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        let _ = client.execute("\
            DELETE FROM users_roles
            WHERE user_id = $1;", &[&user_id])
            .await
            .map_err(|err| err.to_string())?;

        if roles.len() == 0 {
            return Ok(())
        }

        let mut insert_query = String::from("INSERT INTO users_roles (user_id, role_id) VALUES ");
        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new();

        for (i, _) in roles.iter().enumerate() {
            if i > 0 {
                insert_query.push(',');
            }

            insert_query.push_str(&format!("(${}, ${})", 2 * i + 1, 2 * i + 2));

            params.push(&user_id);
            params.push(&roles[i])
        }

        let _ = client.execute(&insert_query, &params[..]).await.map_err(|err| err.to_string())?;

        Ok(())
    }

    async fn get_user_roles(&self, user_id: i32) -> Result<Vec<Role>, String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        let result = client.query("\
            SELECT r.id, r.name, r.created_at, r.updated_at
            FROM users_roles ur
            INNER JOIN roles r
            ON ur.role_id = r.id
            WHERE ur.user_id = $1;", &[&user_id])
            .await
            .map_err(|err| err.to_string())?
            .iter()
            .map(|row| map_to_role(&row))
            .collect();

        Ok(result)
    }

    async fn get_roles(&self) -> Result<Vec<Role>, String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        Ok(client.query(
            SELECT_ALL_FROM_ROLES, &[])
            .await
            .map_err(|err| err.to_string())?
            .iter()
            .map(|row| map_to_role(row))
            .collect())
    }

    async fn get_role(&self, role_id: i32) -> Result<Option<Role>, String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        let query = format!("\
            {SELECT_ALL_FROM_ROLES}
            WHERE id=$1;");
        let row = client.query_opt(&query, &[&role_id])
            .await
            .map_err(|err| err.to_string())?;

        Ok(row.map(|row| map_to_role(&row)))
    }

    async fn get_role_by_name(&self, role_name: &str) -> Result<Option<Role>, String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        let query = format!("\
            {SELECT_ALL_FROM_ROLES}
            WHERE name=$1;");
        let row = client.query_opt(&query, &[&role_name])
            .await
            .map_err(|err| err.to_string())?;

        Ok(row.map(|row| map_to_role(&row)))
    }
}

async fn open_connection(conn_string: &str) -> Result<tokio_postgres::Client, String> {
    let (client, connection) = tokio_postgres::connect(conn_string, NoTls).await.map_err(|err| err.to_string())?;

    tokio::spawn(async move {
        connection.await.unwrap();
    });

    Ok(client)
}

fn map_to_user<TAuthUser: AuthUser + fmt::Debug + Sync + Send>(row: &tokio_postgres::row::Row) -> TAuthUser {
    TAuthUser::existing(
        row.get("id"),
        row.get("username"),
        row.get("pwd_hash"),
        row.get("blocked"),
        row.get("created_at"),
        row.get("updated_at"))
}

fn map_to_role(row: &tokio_postgres::row::Row) -> Role {
    Role::existing(
        row.get("id"),
        row.get("name"),
        row.get("created_at"),
        row.get("updated_at"))
}