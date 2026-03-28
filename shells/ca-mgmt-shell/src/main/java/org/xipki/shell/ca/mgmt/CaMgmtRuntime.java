// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.xipki.ca.mgmt.client.CaMgmtClient;
import org.xipki.shell.ShellUtil;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.extra.http.SslContextConfWrapper;
import org.xipki.util.misc.StringUtil;

import java.io.File;
import java.util.Set;

/**
 * CA Mgmt Runtime.
 *
 * @author Lijun Liao (xipki)
 */
public class CaMgmtRuntime {

  private static final String DEFAULT_MGMT_CONF = "xipki/etc/ca-mgmt-client.json";

  private static CaMgmtClient cachedClient;

  private CaMgmtRuntime() {
  }

  /**
   * Returns the lazily initialized CA management client.
   *
   * @return CA management client
   * @throws Exception on configuration or initialization failure
   */
  public static synchronized CaMgmtClient get() throws Exception {
    String expanded = ShellUtil.resolveRequired(DEFAULT_MGMT_CONF);
    if (cachedClient != null) {
      return cachedClient;
    }

    JsonMap root = JsonParser.parseMap(new File(expanded).toPath(), true);
    boolean useSslConf = root.getBool("useSslConf", false);

    SslContextConfWrapper ssl = new SslContextConfWrapper();
    ssl.setUseSslConf(useSslConf);
    JsonMap sslMap = root.getMap("ssl");
    if (sslMap != null) {
      ssl.setSslStoreType(sslMap.getString("storeType"));
      ssl.setSslKeystore(sslMap.getString("keystore"));
      ssl.setSslKeystorePassword(sslMap.getString("keystorePassword"));
      String hv = sslMap.getString("hostnameVerifier");
      ssl.setSslHostnameVerifier(StringUtil.isBlank(hv) ? "default" : hv);

      Set<String> trustAnchors = sslMap.getStringSet("trustAnchors");
      ssl.setSslTrustanchors(trustAnchors);
    }

    String serverUrl = root.getString("serverUrl");
    if (StringUtil.isBlank(serverUrl)) {
      serverUrl = "https://localhost:8444/ca/mgmt";
    }

    CaMgmtClient client = new CaMgmtClient();
    client.init(ssl, serverUrl);
    client.initIfNotDone();

    cachedClient = client;
    return client;
  }

}
