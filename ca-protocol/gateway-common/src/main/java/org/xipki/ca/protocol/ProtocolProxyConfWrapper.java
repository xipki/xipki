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

package org.xipki.ca.protocol;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.Audits;
import org.xipki.audit.Audits.AuditConf;
import org.xipki.ca.protocol.conf.ProtocolProxyConf;
import org.xipki.ca.protocol.conf.SdkClientConf;
import org.xipki.ca.protocol.conf.SignerConf;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.Securities;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;
import org.xipki.util.http.SslContextConf;

import java.io.IOException;

/**
 * Class to build the protocol proxy from the configuration.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */
public class ProtocolProxyConfWrapper {

  private static final Logger LOG = LoggerFactory.getLogger(ProtocolProxyConfWrapper.class);

  private final Securities securities;

  private final boolean logReqResp;

  private final SdkClient sdkClient;

  private final ConcurrentContentSigner signer;

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
      authenticator = (RequestorAuthenticator)
          Class.forName(clazz).getConstructor().newInstance();
    } catch (Exception e) {
      String msg = "could not load RequestorAuthenticator " + clazz;
      LOG.error(msg, e);
      throw new InvalidConfException(msg);
    }

    popControl = new PopControl(conf.getPop());

    SdkClientConf sdkConf = conf.getSdkClient();
    SslContextConf sdkSslConf = SslContextConf.ofSslConf(sdkConf.getSsl());
    sdkClient = new SdkClient(sdkConf.getServerUrl(),
        sdkSslConf.getSslSocketFactory(), sdkSslConf.buildHostnameVerifier());

    SignerConf signerConf = conf.getSigner();
    signer = (signerConf == null) ? null
            : securities.getSecurityFactory().createSigner(signerConf.getType(),
                new org.xipki.security.SignerConf(signerConf.getConf()),
                X509Util.parseCerts(signerConf.getCerts()).toArray(new X509Cert[0]));
  } // method init

  public Securities getSecurities() {
    return securities;
  }

  public boolean isLogReqResp() {
    return logReqResp;
  }

  public SdkClient getSdkClient() {
    return sdkClient;
  }

  public ConcurrentContentSigner getSigner() {
    return signer;
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
