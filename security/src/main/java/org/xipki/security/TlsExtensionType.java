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

package org.xipki.security;

/**
 * TLS feature extension type. See RFC 7633 for details.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class TlsExtensionType implements Comparable<TlsExtensionType> {

  public static final TlsExtensionType SERVER_NAME = new TlsExtensionType(0, "server_name");
  public static final TlsExtensionType MAX_FRAGMENT_LENGTH = new TlsExtensionType(1, "max_fragment_length");
  public static final TlsExtensionType CLIENT_CERTIFICATE_URL =
      new TlsExtensionType(2, "client_certificate_url");
  public static final TlsExtensionType TRUSTED_CA_KEYS = new TlsExtensionType(3, "trusted_ca_keys");
  public static final TlsExtensionType TRUCATED_HMAC = new TlsExtensionType(4, "truncated_hmac");
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
    return (obj instanceof TlsExtensionType) ? code == ((TlsExtensionType) obj).code : false;
  }
}
