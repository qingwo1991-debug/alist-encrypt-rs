use sqlx::MySqlPool;

pub async fn run_bootstrap_sql(pool: &MySqlPool, sql: &str) -> Result<(), sqlx::Error> {
    for stmt in split_sql_statements(sql) {
        if stmt.trim().is_empty() {
            continue;
        }
        sqlx::query(stmt).execute(pool).await?;
    }
    Ok(())
}

pub fn split_sql_statements(sql: &str) -> Vec<&str> {
    sql.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::split_sql_statements;

    #[test]
    fn split_statements_basic() {
        let sql = "SELECT 1;\n\nSELECT 2;\n";
        let stmts = split_sql_statements(sql);
        assert_eq!(stmts, vec!["SELECT 1", "SELECT 2"]);
    }
}
