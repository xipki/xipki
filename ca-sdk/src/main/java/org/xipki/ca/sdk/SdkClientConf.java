// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.util.JSON;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.http.SslConf;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
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
