// License Apache License 2.0

package org.xipki.mgmt.web.db;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;

/**
 * Runs only the bundled, reviewed schema scripts (no user SQL input).
 *
 * @author palos
 */
final class SqlScripts {
  static void populate(Connection connection, String resource) throws Exception {
    String sql;
    try (var stream = SqlScripts.class.getClassLoader().getResourceAsStream(resource)) {
      if (stream == null) {
        throw new IllegalStateException("Missing schema resource: " + resource);
      }
      sql = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
    }
    sql = sql.replaceAll("(?m)^\\s*--[^\\r\\n]*", "");
    // Bundled scripts contain no procedures or semicolons inside string literals.
    for (String part : sql.split(";")) {
      if (!part.isBlank()) {
        try (var statement = connection.createStatement()) {
          statement.setQueryTimeout(30);
          statement.execute(part.strip());
        }
      }
    }
  }

  private SqlScripts() {}
}
