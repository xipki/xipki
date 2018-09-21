/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.datasource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.IoUtil;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DataSourceFactory {

  private static final Logger LOG = LoggerFactory.getLogger(DataSourceFactory.class);

  public DataSourceWrapper createDataSourceForFile(String name, String confFile,
      PasswordResolver passwordResolver) throws PasswordResolverException, IOException {
    ParamUtil.requireNonNull("confFile", confFile);
    InputStream fileIn = Files.newInputStream(Paths.get(IoUtil.expandFilepath(confFile)));
    return createDataSource(name, fileIn, passwordResolver);
  }

  public DataSourceWrapper createDataSource(String name, InputStream conf,
      PasswordResolver passwordResolver) throws PasswordResolverException, IOException {
    ParamUtil.requireNonNull("conf", conf);
    Properties config = new Properties();
    try {
      config.load(conf);
    } finally {
      try {
        conf.close();
      } catch (Exception ex) {
        LOG.error("could not close stream: {}", ex.getMessage());
      }
    }

    return createDataSource(name, config, passwordResolver);
  } // method createDataSource

  public DataSourceWrapper createDataSource(String name, Properties conf,
      PasswordResolver passwordResolver) throws PasswordResolverException {
    ParamUtil.requireNonNull("conf", conf);
    DatabaseType databaseType;
    String className = conf.getProperty("dataSourceClassName");
    if (className != null) {
      databaseType = DatabaseType.forDataSourceClass(className);
    } else {
      className = conf.getProperty("driverClassName");
      if (className != null) {
        databaseType = DatabaseType.forDriver(className);
      } else {
        String jdbcUrl = conf.getProperty("jdbcUrl");
        if (jdbcUrl == null) {
          throw new IllegalArgumentException("none of the properties dataSourceClassName"
              + ", driverClassName and jdbcUrl is configured");
        }

        databaseType = DatabaseType.forJdbcUrl(jdbcUrl);
      }
    }

    String password = conf.getProperty("password");
    if (password != null) {
      if (passwordResolver != null) {
        password = new String(passwordResolver.resolvePassword(password));
      }
      conf.setProperty("password", password);
    }

    password = conf.getProperty("dataSource.password");
    if (password != null) {
      if (passwordResolver != null) {
        password = new String(passwordResolver.resolvePassword(password));
      }
      conf.setProperty("dataSource.password", password);
    }

    Set<Object> keySet = new HashSet<>(conf.keySet());
    for (Object key : keySet) {
      if (((String) key).startsWith("liquibase")) {
        conf.remove(key);
      }
    }

    return DataSourceWrapper.createDataSource(name, conf, databaseType);
  } // method createDataSource

}
