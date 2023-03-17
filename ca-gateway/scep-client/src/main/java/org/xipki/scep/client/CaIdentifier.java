// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client;

import org.xipki.scep.transaction.Operation;
import org.xipki.scep.transaction.TransactionException;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

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

  public String buildGetUrl(Operation operation) throws TransactionException {
    return buildGetUrl(operation, null);
  }

  public String buildGetUrl(Operation operation, String message) {
    Args.notNull(operation, "operation");
    StringBuilder ub = new StringBuilder(url);
    ub.append('?').append("operation=").append(operation.getCode());

    if (StringUtil.isNotBlank(message)) {
      String urlMessage;
      try {
        urlMessage = URLEncoder.encode(message, "UTF-8");
      } catch (UnsupportedEncodingException ex) {
        urlMessage = URLEncoder.encode(message);
      }
      ub.append("&message=").append(urlMessage);
    }
    return ub.toString();
  }

  public String buildPostUrl(Operation operation) {
    Args.notNull(operation, "operation");
    return url + "?operation=" + operation.getCode();
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder("URL: ").append(url);
    if (StringUtil.isNotBlank(profile)) {
      sb.append(", CA-Ident: ").append(profile);
    }
    return sb.toString();
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
    if (!url.equals(objB.url)) {
      return false;
    }

    if (profile == null) {
      return objB.profile == null;
    } else {
      return profile.equals(objB.profile);
    }
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

}
