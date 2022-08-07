package org.xipki.ca.gateway.conf;

import com.alibaba.fastjson.JSON;
import org.xipki.util.http.SslConf;

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

  public static SdkClientConf decode(byte[] encoded) {
    return JSON.parseObject(encoded, SdkClientConf.class);
  }

}
