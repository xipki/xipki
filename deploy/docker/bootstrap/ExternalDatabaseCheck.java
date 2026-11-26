// License Apache License 2.0

package org.xipki.container;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Verifies that the deployment's least-privilege database identities can reach every required
 * database and that the pre-provisioned XiPKI schemas are recognizable.
 */
public final class ExternalDatabaseCheck {

  private record Target(String owner, String database, String username, String secretName) {}

  private ExternalDatabaseCheck() {}

  /** Runs the database preflight without logging credentials or accepting administrator access. */
  public static void main(String[] args) throws Exception {
    String engine = requiredEnvironment("XIPKI_DATABASE");
    String host = requiredEnvironment("XIPKI_DB_HOST");
    String role = optionalEnvironment("XIPKI_DB_CHECK_ROLE");
    int port = Integer.parseInt(requiredEnvironment("XIPKI_DB_PORT"));
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("XIPKI_DB_PORT must be between 1 and 65535");
    }

    List<Target> targets = role == null ? deploymentTargets() : roleTargets(role);

    DriverManager.setLoginTimeout(5);
    for (Target target : targets) {
      check(engine, host, port, target);
    }
    System.out.printf(
        "XiPKI database preflight passed for %s%s at %s:%d.%n",
        engine, role == null ? "" : " role " + role, host, port);
  }

  /** Returns the fixed first-release database contract used by standalone deployment checks. */
  private static List<Target> deploymentTargets() {
    return List.of(
        new Target("CA", "caconf", "xipki_ca", "ca_db_password"),
        new Target("CA", "ca", "xipki_ca", "ca_db_password"),
        new Target("CA", "ocsp", "xipki_ca", "ca_db_password"),
        new Target("CA", "keypool", "xipki_ca", "ca_db_password"),
        new Target("Gateway", "acme", "xipki_gateway", "gateway_db_password"),
        new Target("OCSP", "ca", "xipki_ocsp", "ocsp_db_password"),
        new Target("OCSP", "ocsp", "xipki_ocsp", "ocsp_db_password"),
        new Target("Console", "xipki_console", "xipki_console", "console_db_password"));
  }

  /**
   * Builds the database contract for one distributed node from its reviewed node.env values.
   * This lets a node prove its own DBA handoff without receiving another role's credentials.
   */
  private static List<Target> roleTargets(String role) {
    String username = requiredEnvironment("XIPKI_DB_USER");
    return switch (role) {
      case "ca" ->
          List.of(
              new Target(
                  "CA", requiredEnvironment("XIPKI_CACONF_DB_NAME"), username, "ca_db_password"),
              new Target(
                  "CA", requiredEnvironment("XIPKI_CA_DB_NAME"), username, "ca_db_password"),
              new Target(
                  "CA", requiredEnvironment("XIPKI_OCSP_DB_NAME"), username, "ca_db_password"),
              new Target(
                  "CA", requiredEnvironment("XIPKI_KEYPOOL_DB_NAME"), username, "ca_db_password"));
      case "console" ->
          List.of(
              new Target(
                  "Console",
                  requiredEnvironment("XIPKI_CONSOLE_DB_NAME"),
                  username,
                  "console_db_password"));
      case "gateway" ->
          List.of(
              new Target(
                  "Gateway",
                  requiredEnvironment("XIPKI_ACME_DB_NAME"),
                  username,
                  "gateway_db_password"));
      case "ocsp" ->
          List.of(
              new Target(
                  "OCSP", requiredEnvironment("XIPKI_CA_DB_NAME"), username, "ocsp_db_password"),
              new Target(
                  "OCSP",
                  requiredEnvironment("XIPKI_OCSP_DB_NAME"),
                  username,
                  "ocsp_db_password"));
      default ->
          throw new IllegalArgumentException(
              "Unsupported XIPKI_DB_CHECK_ROLE: "
                  + role
                  + " (expected ca, console, gateway, or ocsp)");
    };
  }

  /** Opens one role-scoped connection and validates the schema expected in that database. */
  private static void check(String engine, String host, int port, Target target) throws Exception {
    String password = readSecret(target.secretName());
    String url = jdbcUrl(engine, host, port, target.database());
    try (Connection connection = DriverManager.getConnection(url, target.username(), password)) {
      if (target.owner().equals("Console")) {
        checkConsoleSchema(connection, target);
      } else {
        checkXiPkiSchema(connection, target);
      }
    } catch (Exception ex) {
      throw new IllegalStateException(
          "Database preflight failed for "
              + target.owner()
              + " user "
              + target.username()
              + " on database "
              + target.database()
              + ": "
              + ex.getMessage(),
          ex);
    }
  }

  /** Requires the common XiPKI schema marker created by the DBA initialization scripts. */
  private static void checkXiPkiSchema(Connection connection, Target target) throws Exception {
    try (var statement = connection.prepareStatement("SELECT COUNT(*) FROM DBSCHEMA");
        ResultSet result = statement.executeQuery()) {
      if (!result.next()) {
        throw new IllegalStateException("DBSCHEMA could not be read in " + target.database());
      }
    }
  }

  /**
   * Accepts either an empty Console database, which Console initializes atomically, or a known
   * Console schema. A non-empty unknown schema is rejected to avoid writing into the wrong DB.
   */
  private static void checkConsoleSchema(Connection connection, Target target) throws Exception {
    Set<String> tables = new HashSet<>();
    boolean postgres =
        connection.getMetaData().getDatabaseProductName().toLowerCase(Locale.ROOT).contains("postgres");
    try (ResultSet result =
        connection
            .getMetaData()
            .getTables(
                postgres ? null : connection.getCatalog(),
                postgres ? "public" : null,
                "%",
                new String[] {"TABLE", "BASE TABLE"})) {
      while (result.next()) {
        tables.add(result.getString("TABLE_NAME").toLowerCase(Locale.ROOT));
      }
    }
    if (!tables.isEmpty() && !tables.contains("web_schema_version")) {
      throw new IllegalStateException(
          "database " + target.database() + " is non-empty but is not a Console schema");
    }
  }

  /** Builds a bounded-time JDBC URL for one of the two supported deployment databases. */
  private static String jdbcUrl(String engine, String host, int port, String database) {
    return switch (engine) {
      case "mariadb" ->
          "jdbc:mariadb://"
              + host
              + ":"
              + port
              + "/"
              + database
              + "?connectTimeout=5000&socketTimeout=5000";
      case "postgres" ->
          "jdbc:postgresql://"
              + host
              + ":"
              + port
              + "/"
              + database
              + "?connectTimeout=5&socketTimeout=5";
      default ->
          throw new IllegalArgumentException(
              "Unsupported XIPKI_DATABASE: " + engine + " (expected mariadb or postgres)");
    };
  }

  /** Reads one Compose Secret while removing only the line ending commonly added by editors. */
  private static String readSecret(String name) throws Exception {
    Path path = Path.of("/run/secrets", name);
    String value = Files.readString(path, StandardCharsets.UTF_8);
    if (value.endsWith("\r\n")) {
      value = value.substring(0, value.length() - 2);
    } else if (value.endsWith("\n")) {
      value = value.substring(0, value.length() - 1);
    }
    if (value.isEmpty()) {
      throw new IllegalArgumentException("Database Secret is empty: " + name);
    }
    return value;
  }

  /** Returns a required environment setting with a focused configuration error. */
  private static String requiredEnvironment(String name) {
    String value = System.getenv(name);
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("Required environment setting is missing: " + name);
    }
    return value;
  }

  /** Returns one trimmed optional environment value, treating blank input as absent. */
  private static String optionalEnvironment(String name) {
    String value = System.getenv(name);
    return value == null || value.isBlank() ? null : value.trim().toLowerCase(Locale.ROOT);
  }
}
