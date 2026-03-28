// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.xi;

import org.xipki.shell.ShellUtil;
import org.xipki.util.extra.http.Curl;
import org.xipki.util.extra.http.DefaultCurl;

import java.nio.file.Path;

/**
 * Curl Runtime.
 *
 * @author Lijun Liao (xipki)
 */
public class CurlRuntime {

  private static final String DEFAULT_CURL_CONF = "xipki/etc/curl.json";

  private static Curl cachedCurl;

  private CurlRuntime() {
  }

  /**
   * Returns the lazily initialized curl runtime configured from shell home.
   *
   * @return configured curl instance
   */
  public static synchronized Curl get() {
    if (cachedCurl != null) {
      return cachedCurl;
    }

    String expanded = ShellUtil.resolveRequired(DEFAULT_CURL_CONF);

    DefaultCurl curl = new DefaultCurl();
    if (Path.of(expanded).toFile().isFile()) {
      curl.setConfFile(expanded);
    } else {
      curl.setConfFile(null);
      curl.setUseSslConf(false);
    }

    cachedCurl = curl;
    return curl;
  }

}
