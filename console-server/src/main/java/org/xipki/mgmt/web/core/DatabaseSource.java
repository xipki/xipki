// License Apache License 2.0

package org.xipki.mgmt.web.core;

import java.io.PrintWriter;
import java.sql.*;
import java.util.Properties;
import java.util.logging.Logger;
import javax.sql.DataSource;

/**
 * The same bounded direct connections used by the original backend; no connection-pool framework.
 *
 * @author palos
 */
public final class DatabaseSource implements DataSource {
  private final String url, user, password;

  public DatabaseSource(String url, String user, String password) {
    this.url = url;
    this.user = user;
    this.password = password;
  }

  public Connection getConnection() throws SQLException {
    return getConnection(user, password);
  }

  public Connection getConnection(String username, String secret) throws SQLException {
    Properties properties = new Properties();
    properties.setProperty("user", username);
    properties.setProperty("password", secret);
    properties.setProperty("connectTimeout", "3000");
    properties.setProperty("socketTimeout", "5000");
    return DriverManager.getConnection(url, properties);
  }

  public PrintWriter getLogWriter() {
    return null;
  }

  public void setLogWriter(PrintWriter writer) {
    throw new UnsupportedOperationException();
  }

  public void setLoginTimeout(int timeout) {
    throw new UnsupportedOperationException();
  }

  public int getLoginTimeout() {
    return 3;
  }

  public Logger getParentLogger() {
    return Logger.getLogger("org.xipki.mgmt.web");
  }

  public boolean isWrapperFor(Class<?> type) {
    return type.isInstance(this);
  }

  public <T> T unwrap(Class<T> type) throws SQLException {
    if (isWrapperFor(type)) {
      return type.cast(this);
    }
    throw new SQLException("Not a wrapper");
  }
}
