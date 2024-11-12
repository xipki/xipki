// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.datasource;

import org.xipki.util.FileOrValue;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * Configuration of DataSource.
 *
 * @author Lijun Liao (xipki)
 */
public class DataSourceConf extends ValidableConf {

  private FileOrValue conf;

  private String name;

  public FileOrValue getConf() {
    return conf;
  }

  public void setConf(FileOrValue value) {
    this.conf = value;
  }

  public String getName() {
    return name;
  }

  public void setName(String value) {
    this.name = value;
  }

  @Override
  public void validate() throws InvalidConfException {
    notBlank(name, "name");
    notNull(conf, "conf");
    validate(conf);
  }

}

