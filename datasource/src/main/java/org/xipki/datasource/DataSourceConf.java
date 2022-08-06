/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import org.xipki.util.FileOrValue;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * Configuration of DataSource.
 *
 * @author Lijun Liao
 */
public class DataSourceConf extends ValidatableConf {

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
  public void validate()
      throws InvalidConfException {
    notBlank(name, "name");
    notNull(conf, "conf");
    validate(conf);
  }

}

