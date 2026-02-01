// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.acme.AcmeHttpServlet;
import org.xipki.ca.gateway.acme.AcmeProtocolConf;
import org.xipki.ca.gateway.acme.AcmeResponder;
import org.xipki.ca.gateway.cmp.CmpControl;
import org.xipki.ca.gateway.cmp.CmpHttpServlet;
import org.xipki.ca.gateway.cmp.CmpProtocolConf;
import org.xipki.ca.gateway.cmp.CmpResponder;
import org.xipki.ca.gateway.conf.CaNameSignerConf;
import org.xipki.ca.gateway.conf.CaNameSignersConf;
import org.xipki.ca.gateway.conf.CaProfilesControl;
import org.xipki.ca.gateway.conf.GatewayConf;
import org.xipki.ca.gateway.conf.SignerConf;
import org.xipki.ca.gateway.est.EstHttpServlet;
import org.xipki.ca.gateway.est.EstProtocolConf;
import org.xipki.ca.gateway.est.EstResponder;
import org.xipki.ca.gateway.rest.RestHttpServlet;
import org.xipki.ca.gateway.rest.RestProtocolConf;
import org.xipki.ca.gateway.rest.RestResponder;
import org.xipki.ca.gateway.scep.CaNameScepSigners;
import org.xipki.ca.gateway.scep.ScepHttpServlet;
import org.xipki.ca.gateway.scep.ScepProtocolConf;
import org.xipki.ca.gateway.scep.ScepResponder;
import org.xipki.ca.sdk.SdkClient;
import org.xipki.security.ConcurrentSigner;
import org.xipki.security.Securities;
import org.xipki.security.X509Cert;
import org.xipki.security.auth.RequestorAuthenticator;
import org.xipki.security.util.X509Util;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.audit.Audits;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.http.HttpConstants;
import org.xipki.util.extra.http.HttpStatusCode;
import org.xipki.util.extra.http.XiHttpFilter;
import org.xipki.util.extra.http.XiHttpRequest;
import org.xipki.util.extra.http.XiHttpResponse;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.misc.ReflectiveUtil;
import org.xipki.util.io.IoUtil;
import org.xipki.util.io.XipkiBaseDir;
import org.xipki.util.misc.StringUtil;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CMP Gateway ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class GatewayHttpFilter implements XiHttpFilter {

  private static final Logger LOG =
      LoggerFactory.getLogger(GatewayHttpFilter.class);

  private static final String DFLT_CFG = "etc/gateway.json";
  private static final String ACME_CFG = "etc/acme-gateway.json";
  private static final String CMP_CFG  = "etc/cmp-gateway.json";
  private static final String EST_CFG  = "etc/est-gateway.json";
  private static final String REST_CFG = "etc/rest-gateway.json";
  private static final String SCEP_CFG = "etc/scep-gateway.json";

  private AcmeHttpServlet acmeServlet;

  private CmpHttpServlet cmpServlet;

  private EstHttpServlet estServlet;

  private RestHttpServlet restServlet;

  private ScepHttpServlet scepServlet;

  private Securities securities;

  static {
    LOG.info("XiPKI CA Protocol Gateway version {}",
        StringUtil.getBundleVersion(AcmeResponder.class));
  }

  public GatewayHttpFilter() throws Exception {
    XipkiBaseDir.init();

    GatewayConf gatewayConf;
    try {
      gatewayConf = GatewayConf.readConfFromFile(
          IoUtil.expandFilepath(DFLT_CFG, true));
    } catch (IOException ex) {
      throw new IOException("could not parse configuration file " + DFLT_CFG,
          ex);
    } catch (InvalidConfException ex) {
      throw new InvalidConfException(
          "could not parse configuration file " + DFLT_CFG, ex);
    }

    securities = new Securities();
    try {
      securities.init(gatewayConf.security());
    } catch (IOException ex) {
      throw new InvalidConfException("could not initialize Securities", ex);
    }

    Audits.init(gatewayConf.audit().type(),
        gatewayConf.audit().conf());
    if (Audits.getAuditService() == null) {
      throw new InvalidConfException("could not init AuditService");
    }

    SdkClient gSdkClient = new SdkClient(gatewayConf.sdkClient());
    boolean gLogReqResp = gatewayConf.isLogReqResp();
    String reverseProxyMode = gatewayConf.reverseProxyMode();
    PopControl gPopControl = new PopControl(gatewayConf.pop());

    GatewayConf.SupportedProtocols protocols = gatewayConf.protocols();
    boolean enabled = protocols.isAcme();
    LOG.info("ACME is {}", (enabled ? "enabled" : "disabled"));
    if (enabled) {
      initAcme(gLogReqResp, gSdkClient, gPopControl);
    }

    enabled = protocols.isCmp();
    LOG.info("CMP is {}", (enabled ? "enabled" : "disabled"));
    if (enabled) {
      initCmp(gLogReqResp, gSdkClient, gPopControl, reverseProxyMode);
    }

    enabled = protocols.isEst();
    LOG.info("EST is {}", (enabled ? "enabled" : "disabled"));
    if (enabled) {
      initEst(gLogReqResp, gSdkClient, gPopControl, reverseProxyMode);
    }

    enabled = protocols.isRest();
    LOG.info("REST is {}", (enabled ? "enabled" : "disabled"));
    if (enabled) {
      initRest(gLogReqResp, gSdkClient, gPopControl, reverseProxyMode);
    }

    enabled = protocols.isScep();
    LOG.info("SCEP is {}", (enabled ? "enabled" : "disabled"));
    if (enabled) {
      initScep(gLogReqResp, gSdkClient, gPopControl);
    }
    GatewayUtil.auditLogPciEvent(LOG, "Gateway", true, "START");
  }

  private void initAcme(boolean gLogReqResp, SdkClient gSdkClient,
                        PopControl gPopControl) {
    try {
      AcmeProtocolConf pconf = AcmeProtocolConf.readConfFromFile(
          IoUtil.expandFilepath(ACME_CFG, true));

      boolean logReqResp = (pconf.logReqResp() == null)
          ? gLogReqResp : pconf.logReqResp();

      SdkClient sdkClient = gSdkClient;
      if (pconf.sdkClient() != null) {
        sdkClient = new SdkClient(pconf.sdkClient());
        sdkClient.setLogReqResp(logReqResp);
      }

      PopControl popControl = (pconf.pop() == null) ? gPopControl
          : new PopControl(pconf.pop());

      AcmeResponder responder = new AcmeResponder(sdkClient,
          securities.securityFactory(), popControl, pconf.acme());

      responder.start();
      acmeServlet = new AcmeHttpServlet(logReqResp, responder);
      LOG.info("started ACME gateway");
    } catch (Throwable ex) {
      LogUtil.error(LOG, ex, "error starting ACME gateway");
    }
  }

  private void initCmp(boolean gLogReqResp, SdkClient gSdkClient,
                       PopControl gPopControl, String reverseProxyMode) {
    try {
      CmpProtocolConf pconf = CmpProtocolConf.readConfFromFile(
          IoUtil.expandFilepath(CMP_CFG, true));

      boolean logReqResp = (pconf.logReqResp() == null) ? gLogReqResp
          : pconf.logReqResp();

      SdkClient sdkClient = gSdkClient;
      if (pconf.sdkClient() != null) {
        sdkClient = new SdkClient(pconf.sdkClient());
        sdkClient.setLogReqResp(logReqResp);
      }

      PopControl popControl = (pconf.pop() == null) ? gPopControl
          : new PopControl(pconf.pop());

      RequestorAuthenticator authenticator =
          newAuthenticator(pconf.authenticator());
      CaNameSigners signers = newCaSigners(securities, pconf.signers());
      CmpControl cmpControl = new CmpControl(pconf.cmp());

      CmpResponder responder = new CmpResponder(cmpControl, sdkClient,
          securities.securityFactory(), signers, authenticator, popControl);

      cmpServlet = new CmpHttpServlet(logReqResp, reverseProxyMode, responder);
      LOG.info("started CMP gateway");
    } catch (Throwable ex) {
      LogUtil.error(LOG, ex, "error starting CMP gateway");
    }
  }

  private void initEst(boolean gLogReqResp, SdkClient gSdkClient,
                       PopControl gPopControl, String reverseProxyMode) {
    try {
      EstProtocolConf pconf = EstProtocolConf.readConfFromFile(
          IoUtil.expandFilepath(EST_CFG, true));

      boolean logReqResp = (pconf.logReqResp() == null) ? gLogReqResp
          : pconf.logReqResp();

      SdkClient sdkClient = gSdkClient;
      if (pconf.sdkClient() != null) {
        sdkClient = new SdkClient(pconf.sdkClient());
        sdkClient.setLogReqResp(logReqResp);
      }

      PopControl popControl = (pconf.pop() == null) ? gPopControl
          : new PopControl(pconf.pop());

      RequestorAuthenticator authenticator =
          newAuthenticator(pconf.authenticator());
      CaProfilesControl caProfilesControl =
          new CaProfilesControl(pconf.caProfiles());

      EstResponder responder = new EstResponder(sdkClient,
          securities.securityFactory(), authenticator, popControl,
          caProfilesControl, reverseProxyMode);

      estServlet = new EstHttpServlet(logReqResp, responder);
      LOG.info("started EST gateway");
    } catch (Throwable ex) {
      LogUtil.error(LOG, ex, "error starting EST gateway");
    }
  }

  private void initRest(boolean gLogReqResp, SdkClient gSdkClient,
                        PopControl gPopControl, String reverseProxyMode) {
    try {
      RestProtocolConf pconf = RestProtocolConf.readConfFromFile(
          IoUtil.expandFilepath(REST_CFG, true));

      boolean logReqResp = (pconf.logReqResp() == null) ? gLogReqResp
          :  pconf.logReqResp();

      SdkClient sdkClient = gSdkClient;
      if (pconf.sdkClient() != null) {
        sdkClient = new SdkClient(pconf.sdkClient());
        sdkClient.setLogReqResp(logReqResp);
      }

      PopControl popControl = (pconf.pop() == null) ? gPopControl
          : new PopControl(pconf.pop());

      RequestorAuthenticator authenticator =
          newAuthenticator(pconf.authenticator());
      CaProfilesControl caProfilesControl =
          new CaProfilesControl(pconf.caProfiles());

      RestResponder responder = new RestResponder(sdkClient,
          securities.securityFactory(), authenticator, popControl,
          caProfilesControl, reverseProxyMode);

      restServlet = new RestHttpServlet(logReqResp, responder);
      LOG.info("started REST gateway");
    } catch (Throwable ex) {
      LogUtil.error(LOG, ex, "error starting REST gateway");
    }
  }

  private void initScep(boolean gLogReqResp, SdkClient gSdkClient,
                        PopControl gPopControl) {
    try {
      ScepProtocolConf pconf = ScepProtocolConf.readConfFromFile(
          IoUtil.expandFilepath(SCEP_CFG, true));

      boolean logReqResp = (pconf.logReqResp() == null) ? gLogReqResp
          : pconf.logReqResp();

      SdkClient sdkClient = gSdkClient;
      if (pconf.sdkClient() != null) {
        sdkClient = new SdkClient(pconf.sdkClient());
        sdkClient.setLogReqResp(logReqResp);
      }

      PopControl popControl = (pconf.pop() == null) ? gPopControl
          : new PopControl(pconf.pop());

      RequestorAuthenticator authenticator =
          newAuthenticator(pconf.authenticator());
      CaProfilesControl caProfilesControl =
          new CaProfilesControl(pconf.caProfiles());
      CaNameScepSigners signers = new CaNameScepSigners(
          newCaSigners(securities, pconf.signers()));

      ScepResponder responder = new ScepResponder(pconf.scep(),
          sdkClient, securities.securityFactory(), signers,
          authenticator, popControl, caProfilesControl);

      scepServlet = new ScepHttpServlet(logReqResp, responder);
      LOG.info("started SCEP gateway");
    } catch (Throwable ex) {
      LogUtil.error(LOG, ex, "error starting SCEP gateway");
    }
  }

  @Override
  public void destroy() {
    try {
      if (securities != null) {
        securities.close();
        securities = null;
      }
      GatewayUtil.auditLogPciEvent(LOG, "Gateway", true, "SHUTDOWN");
      GatewayUtil.closeAudits(LOG);
    } catch (Exception e) {
      //LOG.error("error closing audit service", e);
    }
  }

  @Override
  public void doFilter(XiHttpRequest req, XiHttpResponse resp)
      throws Exception {
    String path = req.getServletPath();
    if (path.startsWith("/acme/")) {
      if (acmeServlet != null) {
        // 5 = "/acme".length()
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(5));
        acmeServlet.service(req, resp);
      } else {
        resp.sendError(HttpStatusCode.SC_NOT_FOUND);
      }
    } else if (path.startsWith("/cmp/")) {
      if (cmpServlet != null) {
        // 4 = "/cmp".length()
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(4));
        cmpServlet.service(req, resp);
      } else {
        resp.sendError(HttpStatusCode.SC_FORBIDDEN);
      }
    } else if (path.startsWith("/est/")) {
      if (estServlet != null) {
        // 4 = "/est".length()
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(4));
        estServlet.service(req, resp);
      } else {
        resp.sendError(HttpStatusCode.SC_FORBIDDEN);
      }
    } else if (path.startsWith("/rest/")) {
      if (restServlet != null) {
        // 5 = "/rest".length()
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(5));
        restServlet.service(req, resp);
      } else {
        resp.sendError(HttpStatusCode.SC_FORBIDDEN);
      }
    } else if (path.startsWith("/scep/")) {
      if (scepServlet != null) {
        // 5 = "/scep".length()
        req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path.substring(5));
        scepServlet.service(req, resp);
      } else {
        resp.sendError(HttpStatusCode.SC_FORBIDDEN);
      }
    } else {
      resp.sendError(HttpStatusCode.SC_NOT_FOUND);
    }
  }

  private static RequestorAuthenticator newAuthenticator(
      String authenticatorClazz)
      throws InvalidConfException {
    if (authenticatorClazz == null) {
      return null;
    }

    try {
      return ReflectiveUtil.newInstance(authenticatorClazz);
    } catch (ObjectCreationException e) {
      String msg = "could not load RequestorAuthenticator "
          + authenticatorClazz;
      LOG.error(msg, e);
      throw new InvalidConfException(msg);
    }
  }

  private static CaNameSigners newCaSigners(
      Securities securities, CaNameSignersConf signersConf)
      throws InvalidConfException, ObjectCreationException {
    if (signersConf == null) {
      return null;
    }

    ConcurrentSigner defaultSigner =
        buildSigner(securities, signersConf.getDefault());
    List<CaNameSignerConf> signerConfs = signersConf.signers();
    Map<String, ConcurrentSigner> signerMap = null;
    if (signerConfs != null && !signerConfs.isEmpty()) {
      signerMap = new HashMap<>();
      for (CaNameSignerConf m : signerConfs) {
        ConcurrentSigner signer = buildSigner(securities, m.signer());
        for (String name : m.names()) {
          signerMap.put(name, signer);
        }
      }
    }

    return new CaNameSigners(defaultSigner, signerMap);
  }

  private static ConcurrentSigner buildSigner(
      Securities securities, SignerConf signerConf)
      throws InvalidConfException, ObjectCreationException {
    return (signerConf == null) ? null
        : securities.securityFactory().createSigner(signerConf.type(),
            new org.xipki.security.SignerConf(signerConf.conf()),
            X509Util.parseCerts(signerConf.certs())
                .toArray(new X509Cert[0]));
  }

}
