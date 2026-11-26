// License Apache License 2.0

package org.xipki.mgmt.web.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import javax.sql.DataSource;
import org.xipki.mgmt.web.core.Password;
import org.xipki.mgmt.web.security.BuiltinRoles;
import org.xipki.mgmt.web.security.PermissionCatalog;

/** Installs and validates the Console database schema. */
public class WebSchemaInitializer {
  private final DataSource dataSource;
  private final String username;
  private final String password;

  public WebSchemaInitializer(DataSource dataSource, String username, String password) {
    this.dataSource = dataSource;
    this.username = username;
    this.password = password;
  }

  /**
   * Installs the current schema into an empty database or validates an existing current schema.
   * Unknown and partial databases are rejected so startup cannot silently modify unrelated data.
   */
  public void ensureCurrent() {
    try (Connection connection = dataSource.getConnection()) {
      connection.setAutoCommit(false);
      if (isPostgres(connection)) {
        ensurePostgresCurrent(connection);
      } else {
        ensureMariaDbCurrent(connection);
      }
    } catch (Exception ex) {
      throw new IllegalStateException("Web database initialization failed", ex);
    }
  }

  /** Installs or validates the current MariaDB schema under a database-wide advisory lock. */
  private void ensureMariaDbCurrent(Connection connection) throws Exception {
    try (PreparedStatement lock =
        connection.prepareStatement("SELECT GET_LOCK('xipki_web_schema', 30)")) {
      try (ResultSet result = lock.executeQuery()) {
        if (!result.next() || result.getInt(1) != 1) {
          throw new IllegalStateException("Could not lock Web schema");
        }
      }
    }

    try {
      Set<String> tables = tables(connection, null);
      if (tables.isEmpty()) {
        SqlScripts.populate(connection, "db/web-schema.sql");
        seedCurrent(connection);
      } else if (!tables.equals(WebDatabaseHealth.TABLES)) {
        throw new IllegalStateException("Unknown or incomplete Web schema");
      }
      WebDatabaseHealth.verify(connection);
      connection.commit();
    } catch (Exception ex) {
      connection.rollback();
      throw ex;
    } finally {
      try (PreparedStatement unlock =
          connection.prepareStatement("SELECT RELEASE_LOCK('xipki_web_schema')")) {
        unlock.execute();
      }
    }
  }

  /** Installs or validates the current PostgreSQL schema under a transaction-scoped lock. */
  private void ensurePostgresCurrent(Connection connection) throws Exception {
    try {
      execute(connection, "SET LOCAL lock_timeout='30s'");
      try (PreparedStatement lock =
              connection.prepareStatement("SELECT pg_advisory_xact_lock(8675309001)");
          ResultSet ignored = lock.executeQuery()) {
        if (!ignored.next()) {
          throw new IllegalStateException("Could not lock Web schema");
        }
      }

      Set<String> tables = tables(connection, "public");
      if (tables.isEmpty()) {
        SqlScripts.populate(connection, "db/postgresql/web-schema.sql");
        seedCurrent(connection);
      } else if (!tables.equals(WebDatabaseHealth.TABLES)) {
        throw new IllegalStateException("Unknown or incomplete PostgreSQL Web schema");
      }
      WebDatabaseHealth.verify(connection);
      connection.commit();
    } catch (Exception ex) {
      connection.rollback();
      throw ex;
    }
  }

  /** Seeds the schema version, authorization model, and forced-change administrator atomically. */
  private void seedCurrent(Connection connection) throws Exception {
    Password encoder = new Password();
    execute(connection, "INSERT INTO web_schema_version(version) VALUES (6)");
    execute(connection, "INSERT INTO web_authorization_lock(id) VALUES (1)");
    for (String permission : PermissionCatalog.codes()) {
      execute(
          connection,
          "INSERT INTO web_permission(code,description) VALUES (?,?)",
          permission,
          permission);
    }
    for (var role : BuiltinRoles.roles().entrySet()) {
      execute(
          connection,
          "INSERT INTO web_role(name,display_name,description,role_type,builtin)"
              + " VALUES (?,?,?,?,TRUE)",
          role.getKey(),
          role.getKey(),
          role.getKey(),
          BuiltinRoles.PLATFORM_ROLES.contains(role.getKey()) ? "PLATFORM" : "CA");
      for (String permission : role.getValue()) {
        execute(
            connection,
            "INSERT INTO web_role_permission(role_id,permission_id) SELECT r.id,p.id FROM"
                + " web_role r,web_permission p WHERE r.name=? AND p.code=?",
            role.getKey(),
            permission);
      }
    }
    execute(
        connection,
        "INSERT INTO web_user(username,password_hash,display_name,password_change_required)"
            + " VALUES (?,?,?,TRUE)",
        username,
        encoder.encode(password),
        username);
    execute(
        connection,
        "INSERT INTO web_role_binding(user_id,role_name,scope_type) SELECT id,'SUPER_ADMIN',"
            + " 'PLATFORM' FROM web_user WHERE username=?",
        username);
  }

  /** Returns application tables in the active catalog and requested schema. */
  private static Set<String> tables(Connection connection, String schema) throws Exception {
    Set<String> tables = new HashSet<>();
    try (ResultSet result =
        connection
            .getMetaData()
            .getTables(
                connection.getCatalog(),
                schema,
                "%",
                new String[] {"TABLE", "BASE TABLE", "VIEW"})) {
      while (result.next()) {
        tables.add(result.getString("TABLE_NAME").toLowerCase(Locale.ROOT));
      }
    }
    return tables;
  }

  /** Identifies PostgreSQL through JDBC metadata rather than URL parsing. */
  private static boolean isPostgres(Connection connection) throws Exception {
    return connection
        .getMetaData()
        .getDatabaseProductName()
        .toLowerCase(Locale.ROOT)
        .contains("postgresql");
  }

  /** Executes one reviewed schema or seed statement with positional parameters. */
  private static void execute(Connection connection, String sql, Object... args) throws Exception {
    try (PreparedStatement statement = connection.prepareStatement(sql)) {
      if (args != null) {
        for (int i = 0; i < args.length; i++) {
          statement.setObject(i + 1, args[i]);
        }
      }
      statement.executeUpdate();
    }
  }
}
