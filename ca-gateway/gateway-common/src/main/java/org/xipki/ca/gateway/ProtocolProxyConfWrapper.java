// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.Audits;
import org.xipki.audit.Audits.AuditConf;
import org.xipki.ca.gateway.conf.CaNameSignerConf;
import org.xipki.ca.gateway.conf.CaNameSignersConf;
import org.xipki.ca.gateway.conf.ProtocolProxyConf;
import org.xipki.ca.gateway.conf.SignerConf;
import org.xipki.ca.sdk.SdkClient;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.Securities;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Class to build the protocol proxy from the configuration.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class ProtocolProxyConfWrapper {

  private static final Logger LOG = LoggerFactory.getLogger(ProtocolProxyConfWrapper.class);

  private final Securities securities;

  private final boolean logReqResp;

  private final SdkClient sdkClient;

  private final CaNameSigners signers;

  private final RequestorAuthenticator authenticator;

  private final PopControl popControl;

  public ProtocolProxyConfWrapper(ProtocolProxyConf conf)
      throws InvalidConfException, ObjectCreationException {
    XipkiBaseDir.init();

    logReqResp = conf.isLogReqResp();
    LOG.info("logReqResp: {}", logReqResp);

    AuditConf audit = conf.getAudit();
    String auditType = audit.getType();
    if (StringUtil.isBlank(auditType)) {
      auditType = "embed";
    }

    securities = new Securities();
    try {
      securities.init(conf.getSecurity());
    } catch (IOException ex) {
      throw new InvalidConfException("could not initialize Securities", ex);
    }

    String auditConf = audit.getConf();
    Audits.init(auditType, auditConf, securities.getSecurityFactory().getPasswordResolver());
    if (Audits.getAuditService() == null) {
      throw new InvalidConfException("could not AuditService");
    }

    String clazz = conf.getAuthenticator();
    try {
      authenticator = (RequestorAuthenticator) Class.forName(clazz).getConstructor().newInstance();
    } catch (Exception e) {
      String msg = "could not load RequestorAuthenticator " + clazz;
      LOG.error(msg, e);
      throw new InvalidConfException(msg);
    }

    popControl = new PopControl(conf.getPop());
    sdkClient = new SdkClient(conf.getSdkClient());

    CaNameSignersConf signersConf = conf.getSigners();
    if (signersConf == null) {
      signers = null;
    } else {
      ConcurrentContentSigner defaultSigner = buildSigner(signersConf.getDefault());
      CaNameSignerConf[] signerConfs = signersConf.getSigners();
      Map<String, ConcurrentContentSigner> signerMap = null;
      if (signerConfs != null && signerConfs.length > 0) {
        signerMap = new HashMap<>();
        for (CaNameSignerConf m : signerConfs) {
          ConcurrentContentSigner signer = buildSigner(m.getSigner());
          for (String name : m.getNames()) {
            signerMap.put(name, signer);
          }
        }
      }

      signers = new CaNameSigners(defaultSigner, signerMap);
    }
  } // method init

  private ConcurrentContentSigner buildSigner(SignerConf signerConf)
      throws InvalidConfException, ObjectCreationException {
    return (signerConf == null) ? null : securities.getSecurityFactory().createSigner(signerConf.getType(),
        new org.xipki.security.SignerConf(signerConf.getConf()),
        X509Util.parseCerts(signerConf.getCerts()).toArray(new X509Cert[0]));
  }

  public Securities getSecurities() {
    return securities;
  }

  public boolean isLogReqResp() {
    return logReqResp;
  }

  public SdkClient getSdkClient() {
    return sdkClient;
  }

  public CaNameSigners getSigners() {
    return signers;
  }

  public RequestorAuthenticator getAuthenticator() {
    return authenticator;
  }

  public PopControl getPopControl() {
    return popControl;
  }

  public void destroy() {
    if (securities != null) {
      securities.close();
    }

    if (Audits.getAuditService() != null) {
      try {
        Audits.getAuditService().close();
      } catch (Exception ex) {
        LogUtil.error(LOG, ex);
      }
    }
  } // method destroy

}
