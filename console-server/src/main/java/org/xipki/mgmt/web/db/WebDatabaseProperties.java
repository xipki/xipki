// License Apache License 2.0

package org.xipki.mgmt.web.db;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public record WebDatabaseProperties(String url, String username, String password) {
  /** Loads and validates the supported MariaDB or PostgreSQL connection settings. */
  public static WebDatabaseProperties from(Config environment) {
    String url = value(environment, "WEB_DB_URL", "jdbc:mariadb://web-db:3306/xipki_web");
    String username = value(environment, "WEB_DB_USER", "xipki_web");
    String password = secret(environment, "WEB_DB_PASSWORD", "WEB_DB_PASSWORD_FILE");
    if (!url.startsWith("jdbc:mariadb://") && !url.startsWith("jdbc:postgresql://")) {
      throw new IllegalStateException("WEB_DB_URL must use MariaDB or PostgreSQL JDBC");
    }
    if (username.isBlank() || password.isEmpty()) {
      throw new IllegalStateException("Web database credentials are required");
    }
    return new WebDatabaseProperties(url, username, password);
  }

  private static String value(Config environment, String key, String fallback) {
    String value = environment.getProperty(key);
    return value == null || value.isBlank() ? fallback : value;
  }

  private static String secret(Config environment, String key, String fileKey) {
    String inline = environment.getProperty(key);
    String file = environment.getProperty(fileKey);
    if (inline != null && file != null) {
      throw new IllegalStateException("Configure only one of " + key + " and " + fileKey);
    }
    String value = inline;
    try {
      if (value == null && file != null) {
        value = Files.readString(Path.of(file), StandardCharsets.UTF_8);
      }
    } catch (Exception ex) {
      throw new IllegalStateException("Unable to read " + fileKey, ex);
    }
    if (value == null) {
      throw new IllegalStateException("A Web database password is required");
    }
    if (value.endsWith("\r\n")) {
      value = value.substring(0, value.length() - 2);
    } else if (value.endsWith("\n")) {
      value = value.substring(0, value.length() - 1);
    }
    if (value.indexOf('\0') >= 0 || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
      throw new IllegalStateException(
          "Web database password contains unsupported control characters");
    }
    return value;
  }
}
