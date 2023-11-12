// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.hsmproxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.Securities;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.TlsHelper;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ServletException0;
import org.xipki.util.http.XiHttpFilter;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

/**
 * The Servlet Filter of HSM proxy.
 *
 * @author Lijun Liao (xipki)
 */

public class HsmProxyServletFilter implements XiHttpFilter {

  private static class P11ProxyConf extends ValidableConf {

    private boolean logReqResp;

    private String reverseProxyMode;

    private List<FileOrBinary> clientCerts;

    private Securities.SecurityConf security;

    public static P11ProxyConf readConfFromFile(String fileName) throws IOException, InvalidConfException {
      try (InputStream is = Files.newInputStream(Paths.get(fileName))) {
        P11ProxyConf conf = JSON.parseObject(is, P11ProxyConf.class);
        conf.validate();
        return conf;
      }
    }

    public void setLogReqResp(boolean logReqResp) {
      this.logReqResp = logReqResp;
    }

    public boolean isLogReqResp() {
      return logReqResp;
    }

    public String getReverseProxyMode() {
      return reverseProxyMode;
    }

    public void setReverseProxyMode(String reverseProxyMode) {
      this.reverseProxyMode = reverseProxyMode;
    }

    public List<FileOrBinary> getClientCerts() {
      return clientCerts;
    }

    public void setClientCerts(List<FileOrBinary> clientCerts) {
      this.clientCerts = clientCerts;
    }

    public Securities.SecurityConf getSecurity() {
      return security == null ? Securities.SecurityConf.DEFAULT : security;
    }

    public void setSecurity(Securities.SecurityConf security) {
      this.security = security;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(clientCerts, "clientCerts");
      validate(security);
      TlsHelper.checkReverseProxyMode(reverseProxyMode);
    }

  }

  private static final Logger LOG = LoggerFactory.getLogger(HsmProxyServletFilter.class);

  private static final String DFLT_SERVER_CFG = "etc/hsmproxy/hsmproxy.json";

  private HsmProxyResponder responder;

  private Securities securities;

  public HsmProxyServletFilter() throws ServletException0 {
    XipkiBaseDir.init();

    P11ProxyConf conf;
    try {
      conf = P11ProxyConf.readConfFromFile(IoUtil.expandFilepath(DFLT_SERVER_CFG, true));
    } catch (IOException | InvalidConfException ex) {
      throw new ServletException0(
          "could not parse PKCS#11 Proxy configuration file " + DFLT_SERVER_CFG, ex);
    }

    boolean logReqResp = conf.isLogReqResp();
    LOG.info("logReqResp: {}", logReqResp);

    securities = new Securities();
    try {
      securities.init(conf.getSecurity());
    } catch (IOException | InvalidConfException ex) {
      LogUtil.error(LOG, ex, "could not initialize Securities");
      return;
    }

    for (FileOrBinary fb : conf.getClientCerts()) {
      if (fb.getFile() != null) {
        fb.setFile(IoUtil.expandFilepath(fb.getFile(), true));
      }
    }

    List<X509Cert> clientCerts;
    try {
      clientCerts = X509Util.parseCerts(conf.getClientCerts());
    } catch (InvalidConfException ex) {
      throw new ServletException0("could not read clientCerts", ex);
    }

    try {
      this.responder = new HsmProxyResponder(logReqResp, conf.getReverseProxyMode(),
                        securities.getP11CryptServiceFactory(), clientCerts);
    } catch (XiSecurityException | TokenException ex) {
      throw new ServletException0("Error initializing HsmProxyResponder", ex);
    }
  }

  @Override
  public void destroy() {
    if (securities != null) {
      securities.close();
      securities = null;
    }
  }

  @Override
  public void doFilter(XiHttpRequest request, XiHttpResponse response)
      throws IOException, ServletException0 {
    responder.service(request, response);
  }

}
