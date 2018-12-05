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

package org.xipki.ocsp.server.conf;

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class ResponseCacheType extends ValidatableConf {

  private DatasourceType datasource;

  private int validity = 86400;

  public DatasourceType getDatasource() {
    return datasource;
  }

  public void setDatasource(DatasourceType datasource) {
    this.datasource = datasource;
  }

  public int getValidity() {
    return validity;
  }

  public void setValidity(int validity) {
    this.validity = validity;
  }

  @Override
  public void validate() throws InvalidConfException {
    notNull(datasource, "datasource");
  }

}
