// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.GenerationException;
import org.xipki.ca.api.kpgen.KeypairGeneratorFactory;
import org.xipki.ca.api.profile.CertprofileFactory;
import org.xipki.ca.certprofile.xijson.CertprofileFactoryImpl;
import org.xipki.ca.sdk.ErrorResponse;
import org.xipki.ca.sdk.SdkResponse;
import org.xipki.ca.server.CaServerConf.RemoteMgmt;
import org.xipki.ca.server.CaServerConf;
import org.xipki.ca.server.CertPublisherFactoryRegister;
import org.xipki.ca.server.CertprofileFactoryRegister;
import org.xipki.ca.server.SdkResponder;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.publisher.OcspCertPublisherFactory;
import org.xipki.codec.util.Args;
import org.xipki.codec.Base64;
import org.xipki.codec.exception.CodecException;
import org.xipki.pkix.Securities;
import org.xipki.pkix.exception.ErrorCode;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;
import org.xipki.codec.ConfPairs;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.util.audit.Audits.AuditConf;
import org.xipki.util.audit.Audits;
import org.xipki.util.http.HttpConstants;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpFilter;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;
import org.xipki.pkix.util.misc.CollectionUtil;
import org.xipki.pkix.util.misc.LogUtil;
import org.xipki.pkix.util.misc.ReflectiveUtil;
import org.xipki.pkix.util.conf.FileOrBinary;
import org.xipki.pkix.util.io.XipkiIoUtil;
import org.xipki.pkix.util.io.XipkiBaseDir;
import org.xipki.pkix.util.misc.StringUtil;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * CA Http Filter.
 *
 * @author Lijun Liao (xipki)
 */
public class CaHttpFilter implements XiHttpFilter {

  private static final Logger LOG = LoggerFactory.getLogger(CaHttpFilter.class);

  private static final String DFLT_CFG = "etc/ca/ca.json";

  private final Securities securities;

  private final CaManagerImpl caManager;

  private SdkResponder responder;

  private HttpRaServlet raServlet;

  private CaHttpMgmtServlet mgmtServlet;

  public CaHttpFilter() throws Exception {
    XipkiBaseDir.init();

    CaServerConf conf;
    try {
      conf = CaServerConf.readConfFromFile(XipkiIoUtil.expandFilepath(DFLT_CFG, true));
    } catch (InvalidConfException ex) {
      throw new InvalidConfException("could not parse configuration file " + DFLT_CFG, ex);
    }

    boolean logReqResp = conf.isLogReqResp();
    LOG.info("logReqResp: {}", logReqResp);

    AuditConf audit = conf.audit();
    String auditType = audit.type();
    if (StringUtil.isBlank(auditType)) {
      auditType = "embed";
    }

    securities = new Securities();
    securities.init(conf.security());

    int shardId = conf.shardId();
    ConfPairs auditConf = audit.conf();
    if ("file-mac".equals(auditType) || "database-mac".equals(auditType)) {
      auditConf.putPair("shard-id", Integer.toString(shardId));
    }

    Audits.init(auditType, auditConf);
    if (Audits.getAuditService() == null) {
      throw new IllegalStateException("could not init AuditService");
    }

    caManager = new CaManagerImpl();
    caManager.setSecurityFactory(securities.securityFactory());
    caManager.setP11CryptServiceFactory(securities.p11CryptServiceFactory());

    // Certprofiles
    caManager.setCertprofileFactoryRegister(
        initCertprofileFactoryRegister(conf.certprofileFactories()));

    // KeypairGen
    Set<KeypairGeneratorFactory> keypairGeneratorFactories = new HashSet<>();
    if (conf.keypairGeneratorFactories() != null) {
      for (String className : conf.keypairGeneratorFactories()) {
        try {
          KeypairGeneratorFactory factory = ReflectiveUtil.newInstance(className);
          keypairGeneratorFactories.add(factory);
        } catch (GenerationException ex) {
          LOG.error("error creating KeypairGeneratorFactory {} : {}",
              ex.getClass().getName(), ex.getMessage(), ex);
        }
      }
    }

    caManager.setKeyPairGeneratorFactories(keypairGeneratorFactories);

    // Publisher
    CertPublisherFactoryRegister publisherFactoryRegister = new CertPublisherFactoryRegister();
    publisherFactoryRegister.registFactory(new OcspCertPublisherFactory());
    caManager.setCertPublisherFactoryRegister(publisherFactoryRegister);
    caManager.setCaServerConf(conf);
    caManager.startCaSystem();

    LOG.info("ca.noRA: {}", conf.isNoRA());

    if (!conf.isNoRA()) {
      this.responder = new SdkResponder(conf.reverseProxyMode(), caManager);
      raServlet = new HttpRaServlet(logReqResp, responder);
    }

    RemoteMgmt remoteMgmt = conf.remoteMgmt();
    boolean remoteMgmtEnabled = remoteMgmt != null && remoteMgmt.isEnabled();
    LOG.info("remote management is {}", remoteMgmtEnabled ? "enabled" : "disabled");

    if (remoteMgmtEnabled) {
      List<FileOrBinary> certFiles = remoteMgmt.certs();
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
          mgmtServlet = new CaHttpMgmtServlet(caManager, conf.reverseProxyMode(),
                          certs, logReqResp);
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
    certprofileFactoryRegister.registFactory(new CertprofileFactoryImpl());

    // register additional certprofile factories
    if (factories != null) {
      for (String className : factories) {
        try {
          CertprofileFactory factory = ReflectiveUtil.newInstance(className);
          certprofileFactoryRegister.registFactory(factory);
        } catch (GenerationException ex) {
          LogUtil.warn(LOG, ex);
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
        // 3 = "/ra".length()
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(3));
        raServlet.service(req, resp);
      } else {
        resp.sendError(HttpStatusCode.SC_NOT_FOUND);
      }
    } else if (path.startsWith("/mgmt/")) {
      if (mgmtServlet != null) {
        // 5 = "/mgmt".length()
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(5));
        mgmtServlet.service(req, resp);
      } else {
        resp.sendError(HttpStatusCode.SC_FORBIDDEN);
      }
    } else {
      resp.sendError(HttpStatusCode.SC_NOT_FOUND);
    }
  }

  /**
   * REST API exception.
   *
   * @author Lijun Liao (xipki)
   */
  private static class HttpRaServlet {

    private static final Logger LOG = LoggerFactory.getLogger(HttpRaServlet.class);

    private final boolean logReqResp;

    private final SdkResponder responder;

    public HttpRaServlet(boolean logReqResp, SdkResponder responder) {
      this.logReqResp = logReqResp;
      this.responder = Args.notNull(responder, "responder");
    }

    public void service(XiHttpRequest req, XiHttpResponse resp) throws IOException {
      String method = req.getMethod();
      if ("GET".equalsIgnoreCase(method)) {
        service0(req, false).fillResponse(resp);
      } else if ("POST".equalsIgnoreCase(method)) {
        service0(req, true).fillResponse(resp);
      } else {
        resp.setStatus(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
      }
    }

    private HttpResponse service0(XiHttpRequest req, boolean post) throws IOException {
      byte[] reqBody  = null;
      byte[] respBody = null;
      try {
        String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);
        reqBody = post ? XipkiIoUtil.readAllBytesAndClose(req.getInputStream()) : null;

        SdkResponse response = responder.service(path, reqBody, req);
        respBody = response == null ? null : response.encode();
        int httpStatus = HttpStatusCode.SC_OK;
        if (response instanceof ErrorResponse) {
          ErrorCode errCode = ((ErrorResponse) response).code();
          switch (errCode) {
            case UNAUTHORIZED:
            case NOT_PERMITTED:
              httpStatus = HttpStatusCode.SC_UNAUTHORIZED;
              break;
            case BAD_CERT_TEMPLATE:
            case BAD_POP:
            case BAD_REQUEST:
            case INVALID_EXTENSION:
            case UNKNOWN_CERT_PROFILE:
            case UNKNOWN_CERT:
            case ALREADY_ISSUED:
            case CERT_REVOKED:
            case CERT_UNREVOKED:
              httpStatus = HttpStatusCode.SC_BAD_REQUEST;
              break;
            case PATH_NOT_FOUND:
              httpStatus = HttpStatusCode.SC_NOT_FOUND;
              break;
            case CRL_FAILURE:
            case DATABASE_FAILURE:
            case SYSTEM_FAILURE:
            case SYSTEM_UNAVAILABLE:
            default:
              httpStatus = HttpStatusCode.SC_INTERNAL_SERVER_ERROR;
              break;
          }
        }
        return new HttpResponse(httpStatus, "application/cbor", null, respBody);
      } catch (CodecException ex) {
        LOG.error("Error encoding SdkResponse", ex);
        return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
      } catch (RuntimeException ex) {
        LOG.error("RuntimeException thrown, this should not happen!", ex);
        return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
      } finally {
        if (logReqResp && LOG.isDebugEnabled()) {
          String reqBodyStr = reqBody == null ? null : Base64.encodeToString( reqBody, true);
          String respBodyStr = respBody == null ? null : Base64.encodeToString(respBody, true);
          LOG.debug("HTTP RA path: {}\nRequest:\n{}\nResponse:\n{}",
              req.getRequestURI(), reqBodyStr, respBodyStr);
        }
      }
    }

  }

}
