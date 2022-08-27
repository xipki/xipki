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

package org.xipki.p11proxy.servlet;

import com.alibaba.fastjson.JSON;
import org.xipki.security.Securities.SecurityConf;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Configuration of the P11Proxy.
 *
 * @author Lijun Liao
 */
public class P11ProxyConf extends ValidatableConf {

  private SecurityConf security;

  public static P11ProxyConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    notBlank(fileName, "fileName");
    try (InputStream is = Files.newInputStream(Paths.get(fileName))) {
      P11ProxyConf conf = JSON.parseObject(is, P11ProxyConf.class);
      conf.validate();

      return conf;
    }
  }

  public SecurityConf getSecurity() {
    return security == null ? SecurityConf.DEFAULT : security;
  }

  public void setSecurity(SecurityConf security) {
    this.security = security;
  }

  @Override
  public void validate() throws InvalidConfException {
    validate(security);
  }

}
