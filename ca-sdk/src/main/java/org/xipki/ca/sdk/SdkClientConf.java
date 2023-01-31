/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.ca.sdk;

import org.xipki.security.util.JSON;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.http.SslConf;

import java.io.IOException;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class SdkClientConf {

  private String serverUrl;

  private SslConf ssl;

  public String getServerUrl() {
    return serverUrl;
  }

  public void setServerUrl(String serverUrl) {
    this.serverUrl = serverUrl;
  }

  public SslConf getSsl() {
    return ssl;
  }

  public void setSsl(SslConf ssl) {
    this.ssl = ssl;
  }

  public void validate() throws InvalidConfException {
    if (ssl == null) {
      throw new InvalidConfException("ssl must not be null");
    }
    ssl.validate();
  }

  public static SdkClientConf decode(byte[] encoded) throws InvalidConfException {
    SdkClientConf conf = JSON.parseObject(encoded, SdkClientConf.class);
    conf.validate();
    return conf;
  }

  public static SdkClientConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    return decode(IoUtil.read(fileName));
  }

}
