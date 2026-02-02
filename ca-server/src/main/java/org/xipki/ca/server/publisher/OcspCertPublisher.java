// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.publisher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.security.pkix.CertRevocationInfo;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.pkix.X509Crl;
import org.xipki.util.codec.Args;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.datasource.DataAccessException;
import org.xipki.util.datasource.DataSourceMap;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.extra.audit.AuditEvent;
import org.xipki.util.extra.audit.AuditLevel;
import org.xipki.util.extra.audit.AuditStatus;
import org.xipki.util.extra.audit.Audits;
import org.xipki.util.extra.exception.CertPublisherException;

import java.security.NoSuchAlgorithmException;

/**
 * Publish certificates to XiPKI OCSP database.
 *
 * @author Lijun Liao (xipki)
 */

public class OcspCertPublisher extends CertPublisher {

  private static final Logger LOG =
      LoggerFactory.getLogger(OcspCertPublisher.class);

  private OcspStoreQueryExecutor queryExecutor;

  private boolean publishsGoodCert = true;

  public OcspCertPublisher() {
  }

  @Override
  public void initialize(String conf, DataSourceMap datasourceConfs)
      throws CertPublisherException {
    Args.notNull(conf, "conf");

    ConfPairs pairs = new ConfPairs(conf);
    String str = pairs.value("publish.goodcerts");
    this.publishsGoodCert = str == null || Boolean.parseBoolean(str);

    ConfPairs confPairs = new ConfPairs(conf);
    String datasourceName = confPairs.value("datasource");

    DataSourceWrapper datasource = null;
    if (datasourceName != null) {
      datasource = datasourceConfs.getDataSource(datasourceName);
    }

    if (datasource == null) {
      throw new CertPublisherException("no datasource named '"
          + datasourceName + "' is specified");
    }

    try {
      queryExecutor = new OcspStoreQueryExecutor(datasource,
          this.publishsGoodCert);
    } catch (NoSuchAlgorithmException | DataAccessException ex) {
      throw new CertPublisherException(ex.getMessage(), ex);
    }
  } // method initialize

  @Override
  public boolean caAdded(X509Cert issuer) {
    try {
      queryExecutor.addIssuer(issuer);
      return true;
    } catch (Exception ex) {
      logAndAudit(issuer.subjectText(), issuer, null, ex,
          "could not publish issuer");
      return false;
    }
  } // method caAdded

  @Override
  public boolean certificateAdded(CertificateInfo certInfo) {
    X509Cert caCert = certInfo.issuerCert();
    CertWithDbId cert = certInfo.cert();

    try {
      queryExecutor.addCert(caCert, cert, certInfo.revocationInfo());
      return true;
    } catch (Exception ex) {
      logAndAudit(caCert.subjectText(), cert.cert(), cert.certId(),
          ex, "could not save certificate");
      return false;
    }
  } // method certificateAdded

  @Override
  public boolean certificateRevoked(X509Cert caCert, CertWithDbId cert,
      String certprofile, CertRevocationInfo revInfo) {
    try {
      queryExecutor.revokeCert(caCert, cert, revInfo);
      return true;
    } catch (Exception ex) {
      logAndAudit(caCert.subjectText(), cert.cert(), cert.certId(),
          ex, "could not publish revoked certificate");
      return false;
    }
  } // method certificateRevoked

  @Override
  public boolean certificateUnrevoked(X509Cert caCert, CertWithDbId cert) {
    try {
      queryExecutor.unrevokeCert(caCert, cert);
      return true;
    } catch (Exception ex) {
      logAndAudit(caCert.subjectText(), cert.cert(), cert.certId(),
          ex, "could not publish unrevocation of certificate");
      return false;
    }
  } // method certificateUnrevoked

  private void logAndAudit(String issuer, X509Cert cert, Long certId,
                           Exception ex, String messagePrefix) {
    String subjectText = cert.subjectText();
    String serialText = cert.serialNumberHex();

    LOG.error("{} (issuser='{}': subject='{}', serialNumber={}). Message: {}",
        messagePrefix, issuer, subjectText, serialText, ex.getMessage());
    LOG.debug("error", ex);

    AuditEvent event = new AuditEvent("CAPublisher");
    event.setLevel(AuditLevel.ERROR);
    event.setStatus(AuditStatus.FAILED);
    if (certId != null) {
      event.addEventData("id", certId);
    }
    event.addEventData("issuer", issuer);
    event.addEventData("subject", subjectText);
    event.addEventData("serial", serialText);
    event.addEventData("message", messagePrefix);
    Audits.getAuditService().logEvent(event);
  } // method logAndAudit

  @Override
  public boolean crlAdded(X509Cert caCert, X509Crl crl) {
    return true;
  }

  @Override
  public boolean isHealthy() {
    return queryExecutor.isHealthy();
  }

  @Override
  public boolean caRevoked(X509Cert caCert, CertRevocationInfo revInfo) {
    try {
      queryExecutor.revokeCa(caCert, revInfo);
      return true;
    } catch (Exception ex) {
      logAndAudit(caCert.issuerText(), caCert, null, ex,
          "could not publish revocation of CA");
      return false;
    }
  } // method caRevoked

  @Override
  public boolean caUnrevoked(X509Cert caCert) {
    try {
      queryExecutor.unrevokeCa(caCert);
      return true;
    } catch (Exception ex) {
      logAndAudit(caCert.issuerText(), caCert, null, ex,
          "could not publish unrevocation of CA");
      return false;
    }
  } // method caUnrevoked

  @Override
  public boolean certificateRemoved(X509Cert issuerCert, CertWithDbId cert) {
    try {
      queryExecutor.removeCert(issuerCert, cert);
      return true;
    } catch (Exception ex) {
      logAndAudit(issuerCert.issuerText(), issuerCert, null, ex,
          "could not publish removal of certificate");
      return false;
    }
  } // method certificateRemoved

  @Override
  public boolean publishsGoodCert() {
    return publishsGoodCert;
  }

}
