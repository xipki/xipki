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

package org.xipki.ca.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.Audits;
import org.xipki.audit.Audits.AuditConf;
import org.xipki.ca.api.profile.CertprofileFactory;
import org.xipki.ca.api.profile.CertprofileFactoryRegister;
import org.xipki.ca.api.publisher.CertPublisherFactoryRegister;
import org.xipki.ca.certprofile.xijson.CertprofileFactoryImpl;
import org.xipki.ca.server.CaServerConf;
import org.xipki.ca.server.CaServerConf.RemoteMgmt;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.publisher.OcspCertPublisherFactory;
import org.xipki.security.Securities;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * CA ServletFilter.
 *
 * @author Lijun Liao
 */
public class CaServletFilter implements Filter {

  private static final Logger LOG = LoggerFactory.getLogger(CaServletFilter.class);

  private static final String DFLT_CA_SERVER_CFG = "etc/ca/ca.json";

  private Securities securities;

  private CaManagerImpl caManager;

  private HealthCheckServlet healthServlet;

  private HttpCmpServlet cmpServlet;

  private HttpRestServlet restServlet;

  private HttpScepServlet scepServlet;

  private boolean remoteMgmtEnabled;

  private boolean logReqResp;

  private HttpMgmtServlet mgmtServlet;

  @Override
  public void init(FilterConfig filterConfig)
      throws ServletException {
    XipkiBaseDir.init();

    CaServerConf conf;
    try {
      conf = CaServerConf.readConfFromFile(IoUtil.expandFilepath(DFLT_CA_SERVER_CFG, true));
    } catch (IOException | InvalidConfException ex) {
      throw new IllegalArgumentException(
          "could not parse CA configuration file " + DFLT_CA_SERVER_CFG, ex);
    }

    String str = filterConfig.getInitParameter("logReqResp");
    logReqResp = Boolean.parseBoolean(str);
    LOG.info("logReqResp: {}", logReqResp);

    AuditConf audit = conf.getAudit();
    String auditType = audit.getType();
    if (StringUtil.isBlank(auditType)) {
      auditType = "embed";
    }

    String auditConf = audit.getConf();
    Audits.init(auditType, auditConf);

    securities = new Securities();
    try {
      securities.init(conf.getSecurity());
    } catch (IOException | InvalidConfException ex) {
      throw new ServletException("could not initialize Securites", ex);
    }

    caManager = new CaManagerImpl();
    caManager.setSecurityFactory(securities.getSecurityFactory());

    // Certprofiles
    caManager.setCertprofileFactoryRegister(
        initCertprofileFactoryRegister(conf.getCertprofileFactories()));

    // Publisher
    CertPublisherFactoryRegister publiserFactoryRegister = new CertPublisherFactoryRegister();
    publiserFactoryRegister.registFactory(new OcspCertPublisherFactory());
    caManager.setCertPublisherFactoryRegister(publiserFactoryRegister);
    caManager.setCaServerConf(conf);

    caManager.startCaSystem();

    this.cmpServlet = new HttpCmpServlet();
    this.cmpServlet.setResponderManager(caManager);
    this.cmpServlet.setLogReqResp(logReqResp);

    this.healthServlet = new HealthCheckServlet();
    this.healthServlet.setResponderManager(caManager);

    this.restServlet = new HttpRestServlet();
    this.restServlet.setResponderManager(caManager);
    this.restServlet.setLogReqResp(logReqResp);

    this.scepServlet = new HttpScepServlet();
    this.scepServlet.setResponderManager(caManager);
    this.scepServlet.setLogReqResp(logReqResp);

    RemoteMgmt remoteMgmt = conf.getRemoteMgmt();
    this.remoteMgmtEnabled = remoteMgmt != null && remoteMgmt.isEnabled();
    LOG.info("remote management is {}", remoteMgmtEnabled ? "enabled" : "disabled");

    if (this.remoteMgmtEnabled) {
      List<FileOrBinary> certFiles = remoteMgmt.getCerts();
      if (CollectionUtil.isEmpty(certFiles)) {
        LOG.error("no client certificate is configured, disable the remote managent");
      } else {
        Set<X509Cert> certs = new HashSet<>();
        for (FileOrBinary m : certFiles) {
          try {
            X509Cert cert = X509Util.parseCert(m.readContent());
            certs.add(cert);
          } catch (CertificateException | IOException ex) {
            String msg = "could not parse the client certificate";
            if (m.getFile() != null) {
              msg += " " + m.getFile();
            }
            LogUtil.error(LOG, ex, msg);
          }

        }

        if (certs.isEmpty()) {
          LOG.error("could not find any valid client certificates, disable the remote management");
        } else {
          mgmtServlet = new HttpMgmtServlet();
          mgmtServlet.setCaManager(caManager);
          mgmtServlet.setMgmtCerts(certs);
        }
      }
    }
  } // method init

  @Override
  public void destroy() {
    if (securities != null) {
      securities.close();
    }

    if (caManager != null) {
      caManager.close();
    }
  } // method destroy

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (!(request instanceof HttpServletRequest & response instanceof HttpServletResponse)) {
      throw new ServletException("Only HTTP request is supported");
    }

    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse res = (HttpServletResponse) response;

    String path = req.getServletPath();
    if (path.startsWith("/cmp/")) {
      req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(4)); // 4 = "/cmp".length()
      cmpServlet.service(req, res);
    } else if (path.startsWith("/rest/")) {
      req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(5)); // 5 = "/rest".length()
      restServlet.service(req, res);
    } else if (path.startsWith("/scep/")) {
      req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(5)); // 5 = "/scep".length()
      scepServlet.service(req, res);
    } else if (path.startsWith("/health/")) {
      req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(7)); // 7 = "/health".length()
      healthServlet.service(req, res);
    } else if (path.startsWith("/mgmt/")) {
      if (remoteMgmtEnabled) {
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(5)); // 5 = "/mgmt".length()
        mgmtServlet.service(req, res);
      } else {
        sendError(res, HttpServletResponse.SC_FORBIDDEN);
      }
    } else {
      sendError(res, HttpServletResponse.SC_NOT_FOUND);
    }
  } // method doFilter

  private static void sendError(HttpServletResponse res, int status) {
    res.setStatus(status);
    res.setContentLength(0);
  } // method sendError

  private CertprofileFactoryRegister initCertprofileFactoryRegister(List<String> factories) {
    CertprofileFactoryRegister certprofileFactoryRegister = new CertprofileFactoryRegister();
    certprofileFactoryRegister.registFactory(new CertprofileFactoryImpl());

    // register additional CertprofileFactories
    if (factories != null) {
      for (String className : factories) {
        try {
          Class<?> clazz = Class.forName(className);
          CertprofileFactory factory = (CertprofileFactory) clazz.newInstance();
          certprofileFactoryRegister.registFactory(factory);
        } catch (ClassCastException | ClassNotFoundException | IllegalAccessException
            | InstantiationException ex) {
          LOG.error("error caught while initializing CertprofileFactory "
              + className + ": " + ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }
      }
    }

    return certprofileFactoryRegister;
  } // method initCertprofileFactoryRegister

}
