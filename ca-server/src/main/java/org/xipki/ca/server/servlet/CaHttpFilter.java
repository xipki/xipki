// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.Audits;
import org.xipki.audit.Audits.AuditConf;
import org.xipki.ca.api.kpgen.KeypairGeneratorFactory;
import org.xipki.ca.api.profile.CertprofileFactory;
import org.xipki.ca.server.CaServerConf;
import org.xipki.ca.server.CaServerConf.RemoteMgmt;
import org.xipki.ca.server.CertPublisherFactoryRegister;
import org.xipki.ca.server.CertprofileFactoryRegister;
import org.xipki.ca.server.SdkResponder;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.publisher.OcspCertPublisherFactory;
import org.xipki.license.api.LicenseFactory;
import org.xipki.security.Securities;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpFilter;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * CA ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class CaHttpFilter implements XiHttpFilter {

  private static final Logger LOG = LoggerFactory.getLogger(CaHttpFilter.class);

  private static final String XIJSON_CERTFACTORY = "org.xipki.ca.certprofile.xijson.CertprofileFactoryImpl";

  private static final String DFLT_CFG = "etc/ca/ca.json";

  private final Securities securities;

  private final LicenseFactory licenseFactory;

  private final CaManagerImpl caManager;

  private SdkResponder responder;

  private HttpRaServlet raServlet;

  private final boolean remoteMgmtEnabled;

  private CaHttpMgmtServlet mgmtServlet;

  public CaHttpFilter(String licenseFactoryClazz) throws Exception {
    XipkiBaseDir.init();

    CaServerConf conf;
    try {
      conf = CaServerConf.readConfFromFile(IoUtil.expandFilepath(DFLT_CFG, true));
    } catch (IOException ex) {
      throw new IOException("could not parse configuration file " + DFLT_CFG, ex);
    } catch (InvalidConfException ex) {
      throw new InvalidConfException("could not parse configuration file " + DFLT_CFG, ex);
    }

    boolean logReqResp = conf.isLogReqResp();
    LOG.info("logReqResp: {}", logReqResp);

    AuditConf audit = conf.getAudit();
    String auditType = audit.getType();
    if (StringUtil.isBlank(auditType)) {
      auditType = "embed";
    }

    securities = new Securities();
    securities.init(conf.getSecurity());

    int shardId = conf.getShardId();
    String auditConf = audit.getConf();
    if ("file-mac".equals(auditType) || "database-mac".equals(auditType)) {
      auditConf = new ConfPairs(auditConf).putPair("shard-id", Integer.toString(shardId)).getEncoded();
    }

    Audits.init(auditType, auditConf, securities.getSecurityFactory().getPasswordResolver());
    if (Audits.getAuditService() == null) {
      throw new IllegalStateException("could not init AuditService");
    }

    LOG.info("Use licenseFactory: {}", licenseFactoryClazz);
    licenseFactory = (LicenseFactory) Class.forName(licenseFactoryClazz).getDeclaredConstructor().newInstance();

    caManager = new CaManagerImpl(licenseFactory.createCmLicense());
    caManager.setSecurityFactory(securities.getSecurityFactory());
    caManager.setP11CryptServiceFactory(securities.getP11CryptServiceFactory());

    // Certprofiles
    caManager.setCertprofileFactoryRegister(initCertprofileFactoryRegister(conf.getCertprofileFactories()));

    // KeypairGen
    Set<KeypairGeneratorFactory> keypairGeneratorFactories = new HashSet<>();
    if (conf.getKeypairGeneratorFactories() != null) {
      for (String className : conf.getKeypairGeneratorFactories()) {
        try {
          KeypairGeneratorFactory factory = (KeypairGeneratorFactory)
              Class.forName(className).getConstructor().newInstance();
          keypairGeneratorFactories.add(factory);
        } catch (Exception ex) {
          LOG.error("error caught while initializing KeypairGeneratorFactory "
              + className + ": " + ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }
      }
    }

    caManager.setKeyPairGeneratorFactories(keypairGeneratorFactories);

    // Publisher
    CertPublisherFactoryRegister publiserFactoryRegister = new CertPublisherFactoryRegister();
    publiserFactoryRegister.registFactory(new OcspCertPublisherFactory());
    caManager.setCertPublisherFactoryRegister(publiserFactoryRegister);
    caManager.setCaServerConf(conf);

    caManager.startCaSystem();

    LOG.info("ca.noRA: {}", conf.isNoRA());

    if (!conf.isNoRA()) {
      this.responder = new SdkResponder(conf.getReverseProxyMode(), caManager);
      raServlet = new HttpRaServlet(logReqResp, responder);
    }

    RemoteMgmt remoteMgmt = conf.getRemoteMgmt();
    this.remoteMgmtEnabled = remoteMgmt != null && remoteMgmt.isEnabled();
    LOG.info("remote management is {}", remoteMgmtEnabled ? "enabled" : "disabled");

    if (this.remoteMgmtEnabled) {
      List<FileOrBinary> certFiles = remoteMgmt.getCerts();
      if (CollectionUtil.isEmpty(certFiles)) {
        LOG.error("no client certificate is configured, disable the remote management");
      } else {
        List<X509Cert> certs = null;
        try {
          certs = X509Util.parseCerts(certFiles);
        } catch (InvalidConfException ex) {
          LOG.error("error parsing remote management's client certificates", ex);
        }

        if (CollectionUtil.isEmpty(certs)) {
          LOG.error("could not find any valid client certificates, disable the remote management");
        } else {
          mgmtServlet = new CaHttpMgmtServlet(caManager, conf.getReverseProxyMode(), certs);
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

    if (licenseFactory != null) {
      licenseFactory.close();
    }

    if (responder != null) {
      responder.close();
    }

    if (Audits.getAuditService() != null) {
      try {
        Audits.getAuditService().close();
      } catch (Exception ex) {
        LogUtil.error(LOG, ex);
      }
    }
  } // method destroy

  private CertprofileFactoryRegister initCertprofileFactoryRegister(List<String> factories) {
    CertprofileFactoryRegister certprofileFactoryRegister = new CertprofileFactoryRegister();
    try {
      CertprofileFactory certprofileFactory = (CertprofileFactory)
          Class.forName(XIJSON_CERTFACTORY).getConstructor().newInstance();
      certprofileFactoryRegister.registFactory(certprofileFactory);
    } catch (Exception ex) {
      LOG.warn("error initializing " + XIJSON_CERTFACTORY);
    }

    // register additional CertprofileFactories
    if (factories != null) {
      for (String className : factories) {
        try {
          CertprofileFactory factory = (CertprofileFactory) Class.forName(className).getConstructor().newInstance();
          certprofileFactoryRegister.registFactory(factory);
        } catch (Exception ex) {
          LOG.error("error caught while initializing CertprofileFactory "
              + className + ": " + ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }
      }
    }

    return certprofileFactoryRegister;
  } // method initCertprofileFactoryRegister

  @Override
  public void doFilter(XiHttpRequest req, XiHttpResponse resp) throws IOException {
    String path = req.getServletPath();
    if (path.startsWith("/ra/")) {
      if (raServlet != null) {
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(3)); // 3 = "/ra".length()
        raServlet.service(req, resp);
      } else {
        resp.sendError(HttpStatusCode.SC_NOT_FOUND);
      }
    } else if (path.startsWith("/mgmt/")) {
      if (mgmtServlet != null) {
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(5)); // 5 = "/mgmt".length()
        mgmtServlet.service(req, resp);
      } else {
        resp.sendError(HttpStatusCode.SC_FORBIDDEN);
      }
    } else {
      resp.sendError(HttpStatusCode.SC_NOT_FOUND);
    }
  }

}
