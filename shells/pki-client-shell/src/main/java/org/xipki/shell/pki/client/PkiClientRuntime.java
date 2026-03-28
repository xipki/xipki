// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.pki.client;

import org.xipki.cmp.client.CmpClient;
import org.xipki.cmp.client.internal.CmpClientImpl;
import org.xipki.ocsp.client.HttpOcspRequestor;
import org.xipki.scep.client.CaCertValidator;
import org.xipki.scep.client.CaIdentifier;
import org.xipki.scep.client.ScepClient;
import org.xipki.security.Securities;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.shell.ShellUtil;
import org.xipki.shell.security.SecurityRuntime;
import org.xipki.util.extra.http.DefaultCurl;
import org.xipki.util.io.IoUtil;

import java.io.File;
import java.io.IOException;

/**
 * Pki Client Runtime.
 *
 * @author Lijun Liao (xipki)
 */
public class PkiClientRuntime {

  private static final String DEFAULT_CMP_CONF = "xipki/etc/cmp-client.json";

  private static final String DEFAULT_OCSP_CONF = "xipki/etc/ocsp-client.json";

  private static final String DEFAULT_CURL_CONF = "xipki/etc/curl.json";

  private static CmpClientImpl cmpClient;

  private static HttpOcspRequestor ocspRequestor;

  private static DefaultCurl curl;

  /**
   * Returns the lazily initialized CMP client runtime.
   *
   * @return CMP client
   * @throws Exception on configuration or initialization failure
   */
  public static synchronized CmpClient get() throws Exception {
    String expandedCmpConf = resolveRequired(DEFAULT_CMP_CONF);
    if (cmpClient != null) {
      return cmpClient;
    }

    Securities securities = SecurityRuntime.get();

    cmpClient = new CmpClientImpl();
    cmpClient.setSecurityFactory(securities.securityFactory());
    cmpClient.setConfFile(expandedCmpConf);
    cmpClient.init();

    return cmpClient;
  }

  /**
   * Returns the shared security runtime used by PKI client commands.
   *
   * @return security runtime
   * @throws Exception on configuration or initialization failure
   */
  public static Securities getSecurities() throws Exception {
    return SecurityRuntime.get();
  }

  /**
   * Returns the lazily initialized OCSP requestor runtime.
   *
   * @return OCSP requestor
   * @throws Exception on configuration or initialization failure
   */
  public static synchronized HttpOcspRequestor getOcspRequestor() throws Exception {
    Securities secs = getSecurities();
    if (ocspRequestor != null) {
      return ocspRequestor;
    }

    ocspRequestor = new HttpOcspRequestor();
    ocspRequestor.setSecurityFactory(secs.securityFactory());
    ocspRequestor.setConfFile(ShellUtil.resolveOptional(DEFAULT_OCSP_CONF));
    ocspRequestor.init();
    return ocspRequestor;
  }

  /**
   * Creates a SCEP client for the given CA identifier and optional CA certificate file.
   *
   * @param url SCEP endpoint URL
   * @param caId CA identifier
   * @param caCertFile optional CA certificate file
   * @return initialized SCEP client
   * @throws Exception on configuration or initialization failure
   */
  public static synchronized ScepClient getScepClient(
      String url, String caId, String caCertFile) throws Exception {
    if (curl == null) {
      curl = new DefaultCurl();
      curl.setConfFile(ShellUtil.resolveRequired(DEFAULT_CURL_CONF));
    }

    X509Cert caCert = X509Util.parseCert(new File(IoUtil.expandFilepath(caCertFile)));
    CaCertValidator caCertValidator = new CaCertValidator.PreprovisionedCaCertValidator(caCert);
    return new ScepClient(new CaIdentifier(url, caId), caCertValidator, curl);
  }

  private static String resolveRequired(String relativePath) throws IOException {
    String path = ShellUtil.resolveOptional(relativePath);
    if (!new File(path).isFile()) {
      throw new IOException("required config file not found: " + path);
    }
    return path;
  }

}
