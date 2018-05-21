/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.scep.client;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

import org.xipki.scep.transaction.Operation;
import org.xipki.scep.transaction.TransactionException;
import org.xipki.scep.util.ScepUtil;

/**
 * CA identifier.
 * @author Lijun Liao
 */

public class CaIdentifier {

  private final String url;

  private final String profile;

  public CaIdentifier(String serverUrl, String profile) throws MalformedURLException {
    ScepUtil.requireNonBlank("serverUrl", serverUrl);
    URL tmpUrl = new URL(serverUrl);
    final String protocol = tmpUrl.getProtocol();

    if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
      throw new IllegalArgumentException(
          "URL protocol should be HTTP or HTTPS, but not '" + protocol + "'");
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

  @SuppressWarnings("deprecation")
  public String buildGetUrl(Operation operation, String message) {
    ScepUtil.requireNonNull("operation", operation);
    StringBuilder ub = new StringBuilder(url);
    ub.append('?').append("operation=").append(operation.getCode());

    if (message != null && !message.isEmpty()) {
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
    ScepUtil.requireNonNull("operation", operation);
    StringBuilder ub = new StringBuilder(url);
    ub.append('?').append("operation=").append(operation.getCode());
    return ub.toString();
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("URL: ").append(url);
    if (profile != null && !profile.isEmpty()) {
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
