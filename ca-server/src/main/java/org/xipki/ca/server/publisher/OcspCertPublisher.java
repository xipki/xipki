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

package org.xipki.ca.server.publisher;

import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.audit.Audits;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.ConfPairs;
import org.xipki.util.FileOrValue;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.util.Date;
import java.util.Map;

/**
 * Publish certificates to XiPKI OCSP database.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspCertPublisher extends CertPublisher {

  private static final Logger LOG = LoggerFactory.getLogger(OcspCertPublisher.class);

  private OcspStoreQueryExecutor queryExecutor;

  private boolean publishsGoodCert = true;

  private DataSourceWrapper datasource;

  public OcspCertPublisher() {
  }

  @Override
  public void initialize(String conf, PasswordResolver passwordResolver,
      Map<String, FileOrValue> datasourceConfs)
          throws CertPublisherException {
    Args.notNull(conf, "conf");

    ConfPairs pairs = new ConfPairs(conf);
    String str = pairs.value("publish.goodcerts");
    this.publishsGoodCert = str == null || Boolean.parseBoolean(str);

    ConfPairs confPairs = new ConfPairs(conf);
    String datasourceName = confPairs.value("datasource");

    FileOrValue datasourceConf = null;
    if (datasourceName != null) {
      datasourceConf = datasourceConfs.get(datasourceName);
    }

    if (datasourceConf == null) {
      throw new CertPublisherException("no datasource named '" + datasourceName + "' is specified");
    }

    datasource = loadDatasource(datasourceName, datasourceConf, passwordResolver);

    try {
      queryExecutor = new OcspStoreQueryExecutor(datasource, this.publishsGoodCert);
    } catch (NoSuchAlgorithmException | DataAccessException ex) {
      throw new CertPublisherException(ex.getMessage(), ex);
    }
  } // method initialize

  private DataSourceWrapper loadDatasource(String datasourceName, FileOrValue datasourceConf,
      PasswordResolver passwordResolver)
          throws CertPublisherException {
    try {
      DataSourceWrapper datasource = new DataSourceFactory().createDataSource(
          datasourceName, datasourceConf, passwordResolver);

      // test the datasource
      Connection conn = datasource.getConnection();
      datasource.returnConnection(conn);

      LOG.info("loaded datasource.{}", datasourceName);
      return datasource;
    } catch (DataAccessException | PasswordResolverException | IOException
        | RuntimeException ex) {
      throw new CertPublisherException(
          ex.getClass().getName() + " while parsing datasource " + datasourceName + ": "
              + ex.getMessage(),
          ex);
    }
  } // method loadDatasource

  @Override
  public boolean caAdded(X509Cert issuer) {
    try {
      queryExecutor.addIssuer(issuer);
      return true;
    } catch (Exception ex) {
      logAndAudit(issuer.getSubjectRfc4519Text(),
          issuer, null, ex, "could not publish issuer");
      return false;
    }
  } // method caAdded

  @Override
  public boolean certificateAdded(CertificateInfo certInfo) {
    X509Cert caCert = certInfo.getIssuerCert();
    CertWithDbId cert = certInfo.getCert();

    try {
      queryExecutor.addCert(caCert, cert, certInfo.getRevocationInfo());
      return true;
    } catch (Exception ex) {
      logAndAudit(caCert.getSubjectRfc4519Text(),
          cert.getCert(), cert.getCertId(), ex,
          "could not save certificate");
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
      logAndAudit(caCert.getSubjectRfc4519Text(),
          cert.getCert(), cert.getCertId(), ex,
          "could not publish revoked certificate");
      return false;
    }
  } // method certificateRevoked

  @Override
  public boolean certificateUnrevoked(X509Cert caCert, CertWithDbId cert) {
    try {
      queryExecutor.unrevokeCert(caCert, cert);
      return true;
    } catch (Exception ex) {
      logAndAudit(caCert.getSubjectRfc4519Text(),
          cert.getCert(), cert.getCertId(), ex,
          "could not publish unrevocation of certificate");
      return false;
    }
  } // method certificateUnrevoked

  private void logAndAudit(String issuer, X509Cert cert, Long certId, Exception ex,
      String messagePrefix) {
    String subjectText = cert.getSubjectRfc4519Text();
    String serialText = cert.getSerialNumberHex();

    LOG.error("{} (issuser='{}': subject='{}', serialNumber={}). Message: {}",
        messagePrefix, issuer, subjectText, serialText, ex.getMessage());
    LOG.debug("error", ex);

    AuditEvent event = new AuditEvent(new Date());
    event.setApplicationName("CAPublisher");
    event.setName("SYSTEM");
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
  public boolean crlAdded(X509Cert caCert, X509CRLHolder crl) {
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
      logAndAudit(caCert.getIssuerRfc4519Text(),
          caCert, null, ex, "could not publish revocation of CA");
      return false;
    }
  } // method caRevoked

  @Override
  public boolean caUnrevoked(X509Cert caCert) {
    try {
      queryExecutor.unrevokeCa(caCert);
      return true;
    } catch (Exception ex) {
      logAndAudit(caCert.getIssuerRfc4519Text(),
          caCert, null, ex,
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
      logAndAudit(issuerCert.getIssuerRfc4519Text(),
          issuerCert, null, ex,
          "could not publish removal of certificate");
      return false;
    }
  } // method certificateRemoved

  @Override
  public boolean publishsGoodCert() {
    return publishsGoodCert;
  }

  @Override
  public void close() {
    if (datasource != null) {
      datasource.close();
    }

  }

}
