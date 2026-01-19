// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.http;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.io.FileOrBinary;

/**
 * Configuration of SSL.
 *
 * @author Lijun Liao (xipki)
 */
public class SslConf {

  private final String name;

  private final String storeType;

  private final FileOrBinary keystore;

  private final String keystorePassword;

  private final FileOrBinary[] trustanchors;

  /**
   * Valid values are {@code null}, no_op, default, or
   * java:{qualified class name} (without the brackets).
   */
  private final String hostnameVerifier;

  public SslConf(String name, String storeType, String keystorePassword,
                 FileOrBinary keystore, FileOrBinary[] trustanchors,
                 String hostnameVerifier) {
    this.name = name;
    this.storeType = storeType;
    this.keystore = keystore;
    this.keystorePassword = keystorePassword;
    this.trustanchors = trustanchors;
    this.hostnameVerifier = hostnameVerifier;
  }

  public String getName() {
    return name;
  }

  public String getStoreType() {
    return storeType;
  }

  public FileOrBinary getKeystore() {
    return keystore;
  }

  public String getKeystorePassword() {
    return keystorePassword;
  }

  public FileOrBinary[] getTrustanchors() {
    return trustanchors;
  }

  public String getHostnameVerifier() {
    return hostnameVerifier;
  }

  public static SslConf parse(JsonMap json) throws CodecException {
    return new SslConf(json.getString("name"),
        json.getString("storeType"),
        json.getString("keystorePassword"),
        FileOrBinary.parse(json.getMap("keystore")),
        FileOrBinary.parseArray(json.getList("trustanchors")),
        json.getString("hostnameVerifier"));
  }

}
