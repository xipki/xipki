// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client;

import org.xipki.scep.transaction.Operation;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * CA identifier.
 * @author Lijun Liao (xipki)
 */

public class CaIdentifier {

  private final String url;

  private final String profile;

  public CaIdentifier(String serverUrl, String profile) throws MalformedURLException {
    Args.notBlank(serverUrl, "serverUrl");
    URL tmpUrl = new URL(serverUrl);
    final String protocol = tmpUrl.getProtocol();

    if (!StringUtil.orEqualsIgnoreCase(protocol, "http", "https")) {
      throw new IllegalArgumentException("URL protocol should be HTTP or HTTPS, but not '" + protocol + "'");
    }

    if (tmpUrl.getQuery() != null) {
      throw new IllegalArgumentException("URL should contain no query string");
    }

    this.url = serverUrl;
    this.profile = profile;
  }

  public String getUrl() {
    return url;
  }

  public String getProfile() {
    return profile;
  }

  public String buildGetUrl(Operation operation) {
    return buildGetUrl(operation, null);
  }

  public String buildGetUrl(Operation operation, String message) {
    String str = url + "?operation=" + Args.notNull(operation, "operation").getCode();
    return StringUtil.isBlank(message) ? str
        : str + "&message=" + URLEncoder.encode(message, StandardCharsets.UTF_8);
  }

  public String buildPostUrl(Operation operation) {
    return url + "?operation=" + Args.notNull(operation, "operation").getCode();
  }

  @Override
  public String toString() {
    return StringUtil.isBlank(profile)
        ? "URL: " + url
        : "URL: " + url + ", CA-Ident: " + profile;
  }

  @Override
  public boolean equals(Object object) {
    if (this == object) {
      return true;
    }

    if (!(object instanceof CaIdentifier)) {
      return false;
    }

    CaIdentifier objB = (CaIdentifier) object;
    return url.equals(objB.url) && Objects.equals(profile, objB.profile);
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

}
