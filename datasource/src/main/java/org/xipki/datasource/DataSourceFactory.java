// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.datasource;

import org.xipki.password.PasswordResolverException;
import org.xipki.password.Passwords;
import org.xipki.util.Args;
import org.xipki.util.ConfigurableProperties;
import org.xipki.util.FileOrValue;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * Factory to create {@link DataSourceWrapper}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class DataSourceFactory {

  public DataSourceWrapper createDataSource(String name, FileOrValue conf) throws IOException, InvalidConfException {
    ConfigurableProperties props;
    try (Reader reader = new StringReader(Args.notNull(conf, "conf").readContent())) {
      props = new ConfigurableProperties();
      props.load(reader);
    }

    return createDataSource(name, props);
  } // method createDataSource

  /**
   * Create a {@link DataSourceWrapper} from the configuration stored in the input stream.
   * The specified stream remains open after this method returns.
   * @param name the datasource name
   * @param conf the configuration
   * @return the created datasource wrapper.
   * @throws IOException if IO error occurs while reading the input sstream.
   */
  public DataSourceWrapper createDataSource(String name, InputStream conf) throws IOException, InvalidConfException {
    ConfigurableProperties config = new ConfigurableProperties();
    config.load(Args.notNull(conf, "conf"));
    return createDataSource(name, config);
  } // method createDataSource

  public DataSourceWrapper createDataSource(String name, ConfigurableProperties conf) throws InvalidConfException {
    DatabaseType databaseType;
    String className = Args.notNull(conf, "conf").getProperty("dataSourceClassName");
    if (className != null) {
      databaseType = DatabaseType.forDataSourceClass(className);
    } else {
      className = conf.getProperty("driverClassName");
      if (className != null) {
        databaseType = DatabaseType.forDriver(className);
      } else {
        String jdbcUrl = Optional.ofNullable(conf.getProperty("jdbcUrl")).orElseThrow(() ->
            new IllegalArgumentException("none of the properties dataSourceClassName"
              + ", driverClassName and jdbcUrl is configured"));

        databaseType = DatabaseType.forJdbcUrl(jdbcUrl);
      }
    }

    try {
      String password = conf.getProperty("password");
      if (password != null) {
        password = new String(Passwords.resolvePassword(password));
        conf.setProperty("password", password);
      }

      password = conf.getProperty("dataSource.password");
      if (password != null) {
        password = new String(Passwords.resolvePassword(password));
        conf.setProperty("dataSource.password", password);
      }
    } catch (PasswordResolverException ex) {
      throw new InvalidConfException("error resolving password");
    }

    /*
     * Expand the file path like
     *   dataSource.url = jdbc:h2:~/xipki/db/h2/ocspcrl
     *   dataSource.url = jdbc:hsqldb:file:~/xipki/db/hsqldb/ocspcache;sql.syntax_pgs=true
     */
    String dataSourceUrl = conf.getProperty("dataSource.url");
    if (dataSourceUrl == null) {
      // mariadb
      if (databaseType == DatabaseType.MARIADB) {
        String serverName = conf.remove("dataSource.serverName");
        String port = conf.remove("dataSource.port");
        if (port == null) {
          port = "3306";
        }
        String databaseName = conf.remove("dataSource.databaseName");
        dataSourceUrl = "jdbc:mariadb://" + serverName + ":" + port + "/" + databaseName;
        conf.setProperty("dataSource.url", dataSourceUrl);
      }
    } else {
      String newUrl = null;

      final String h2_prefix = "jdbc:h2:";
      final String hsqldb_prefix = "jdbc:hsqldb:file:";

      if (dataSourceUrl.startsWith(h2_prefix + "~")) {
        newUrl = h2_prefix + IoUtil.expandFilepath(dataSourceUrl.substring(h2_prefix.length()));
      } else if (dataSourceUrl.startsWith(hsqldb_prefix + "~")) {
        newUrl = hsqldb_prefix + IoUtil.expandFilepath(dataSourceUrl.substring(hsqldb_prefix.length()));
      }
      if (newUrl != null) {
        conf.setProperty("dataSource.url", newUrl);
      }
    }

    for (String key : conf.propertyNames()) {
      if (key.startsWith("sqlscript.") || key.startsWith("liquibase.")) {
        conf.remove(key);
      }
    }

    return DataSourceWrapper.createDataSource(name, conf, databaseType);
  } // method createDataSource

  public DataSourceWrapper createDataSourceForFile(String name, String confFile)
      throws IOException, InvalidConfException {
    String path = IoUtil.expandFilepath(Args.notBlank(confFile, "confFile"));
    try (InputStream fileIn = Files.newInputStream(Paths.get(path))) {
      return createDataSource(name, fileIn);
    }
  }

}
