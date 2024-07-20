// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

/**
 * TLS feature extension type. See RFC 7633 for details.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class TlsExtensionType implements Comparable<TlsExtensionType> {

  public static final TlsExtensionType SERVER_NAME = new TlsExtensionType(0, "server_name");
  public static final TlsExtensionType MAX_FRAGMENT_LENGTH = new TlsExtensionType(1, "max_fragment_length");
  public static final TlsExtensionType CLIENT_CERTIFICATE_URL =
      new TlsExtensionType(2, "client_certificate_url");
  public static final TlsExtensionType TRUSTED_CA_KEYS = new TlsExtensionType(3, "trusted_ca_keys");
  public static final TlsExtensionType TRUNCATED_HMAC = new TlsExtensionType(4, "truncated_hmac");
  public static final TlsExtensionType STATUS_REQUEST = new TlsExtensionType(5, "status_request");

  private final int code;
  private final String name;

  private TlsExtensionType(int code, String name) {
    this.code = code;
    this.name = name;
  }

  public int getCode() {
    return code;
  }

  public String getName() {
    return name;
  }

  @Override
  public int compareTo(TlsExtensionType obj) {
    return Integer.compare(code, obj.code);
  }

  @Override
  public int hashCode() {
    return code;
  }

  @Override
  public boolean equals(Object obj) {
    return obj instanceof TlsExtensionType && code == ((TlsExtensionType) obj).code;
  }
}
