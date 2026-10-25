// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.util.http.SslConf;
import org.xipki.codec.util.IoUtil;

import java.io.IOException;

/**
 * Sdk Client configuration.
 *
 * @author Lijun Liao (xipki)
 */
public class SdkClientConf {

  private final String serverUrl;

  private final SslConf ssl;

  public SdkClientConf(String serverUrl, SslConf ssl) {
    this.serverUrl = serverUrl;
    this.ssl = Args.notNull(ssl, "ssl");
  }

  public String serverUrl() {
    return serverUrl;
  }

  public SslConf ssl() {
    return ssl;
  }

  public static SdkClientConf parse(JsonMap json) throws CodecException {
    JsonMap map = json.getMap("ssl");
    SslConf ssl = (map == null) ? null : SslConf.parse(map);

    return new SdkClientConf(json.getString("serverUrl"), ssl);
  }

  public static SdkClientConf decode(byte[] encoded) throws InvalidConfException {
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
