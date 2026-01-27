// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.http.SslConf;
import org.xipki.util.io.IoUtil;

import java.io.IOException;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class SdkClientConf {

  private final String serverUrl;

  private final SslConf ssl;

  public SdkClientConf(String serverUrl, SslConf ssl) {
    this.serverUrl = serverUrl;
    this.ssl = Args.notNull(ssl, "ssl");
  }

  public String getServerUrl() {
    return serverUrl;
  }

  public SslConf getSsl() {
    return ssl;
  }

  public static SdkClientConf parse(JsonMap json) throws CodecException {
    JsonMap map = json.getMap("ssl");
    SslConf ssl = (map == null) ? null : SslConf.parse(map);

    return new SdkClientConf(json.getString("serverUrl"), ssl);
  }

  public static SdkClientConf decode(byte[] encoded)
      throws IOException, InvalidConfException {
    try {
      JsonMap root = JsonParser.parseMap(encoded, true);
      return parse(root);
    } catch (CodecException e) {
      throw new InvalidConfException(e);
    }
  }

  public static SdkClientConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    return decode(IoUtil.read(fileName));
  }

}
