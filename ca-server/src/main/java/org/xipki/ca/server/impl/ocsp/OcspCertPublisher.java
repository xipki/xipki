/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.server.impl.ocsp;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditServiceRegister;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.api.EnvParameterResolver;
import org.xipki.ca.api.X509CertWithDbId;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.x509.X509CertPublisher;
import org.xipki.ca.api.publisher.x509.X509CertificateInfo;
import org.xipki.ca.server.impl.CaAuditConstants;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.password.PasswordResolver;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspCertPublisher extends X509CertPublisher {

    private static final Logger LOG = LoggerFactory.getLogger(OcspCertPublisher.class);

    @SuppressWarnings("unused")
    private EnvParameterResolver envParameterResolver;

    private OcspStoreQueryExecutor queryExecutor;

    private boolean asyn;

    private boolean publishsGoodCert = true;

    private AuditServiceRegister auditServiceRegister;

    public OcspCertPublisher() {
    }

    @Override
    public void initialize(final String conf, final PasswordResolver passwordResolver,
            final Map<String, DataSourceWrapper> datasources) throws CertPublisherException {
        ParamUtil.requireNonNull("conf", conf);
        ParamUtil.requireNonEmpty("datasources", datasources);

        ConfPairs utf8pairs = new ConfPairs(conf);
        String str = utf8pairs.value("publish.goodcerts");
        this.publishsGoodCert = (str == null) ? true : Boolean.parseBoolean(str);

        str = utf8pairs.value("asyn");
        this.asyn = (str == null) ? false : Boolean.parseBoolean(str);

        ConfPairs confPairs = new ConfPairs(conf);
        String datasourceName = confPairs.value("datasource");

        DataSourceWrapper datasource = null;
        if (datasourceName != null) {
            datasource = datasources.get(datasourceName);
        }

        if (datasource == null) {
            throw new CertPublisherException(
                    "no datasource named '" + datasourceName + "' is specified");
        }

        try {
            queryExecutor = new OcspStoreQueryExecutor(datasource, this.publishsGoodCert);
        } catch (NoSuchAlgorithmException | DataAccessException ex) {
            throw new CertPublisherException(ex.getMessage(), ex);
        }
    } // method initialize

    @Override
    public void setEnvParameterResolver(final EnvParameterResolver parameterResolver) {
        this.envParameterResolver = parameterResolver;
    }

    @Override
    public boolean caAdded(final X509Cert issuer) {
        try {
            queryExecutor.addIssuer(issuer);
            return true;
        } catch (Exception ex) {
            logAndAudit(issuer.subject(), issuer, ex, "could not publish issuer");
            return false;
        }
    }

    @Override
    public boolean certificateAdded(final X509CertificateInfo certInfo) {
        X509Cert caCert = certInfo.issuerCert();
        X509CertWithDbId cert = certInfo.cert();

        try {
            queryExecutor.addCert(caCert, cert, certInfo.profile().name(),
                    certInfo.revocationInfo());
            return true;
        } catch (Exception ex) {
            logAndAudit(caCert.subject(), cert, ex, "could not save certificate");
            return false;
        }
    }

    @Override
    public boolean certificateRevoked(final X509Cert caCert, final X509CertWithDbId cert,
            final String certprofile, final CertRevocationInfo revInfo) {
        try {
            queryExecutor.revokeCert(caCert, cert, certprofile, revInfo);
            return true;
        } catch (Exception ex) {
            logAndAudit(caCert.subject(), cert, ex, "could not publish revoked certificate");
            return false;
        }
    }

    @Override
    public boolean certificateUnrevoked(final X509Cert caCert, final X509CertWithDbId cert) {
        try {
            queryExecutor.unrevokeCert(caCert, cert);
            return true;
        } catch (Exception ex) {
            logAndAudit(caCert.subject(), cert, ex,
                    "could not publish unrevocation of certificate");
            return false;
        }
    }

    private void logAndAudit(final String issuer, final X509Cert cert, final Exception ex,
            final String messagePrefix) {
        String subjectText = cert.subject();
        String serialText = LogUtil.formatCsn(cert.cert().getSerialNumber());

        LOG.error("{} (issuser='{}': subject='{}', serialNumber={}). Message: {}",
                messagePrefix, issuer, subjectText, serialText, ex.getMessage());
        LOG.debug("error", ex);

        AuditEvent event = new AuditEvent(new Date());
        event.setApplicationName("CAPublisher");
        event.setName("SYSTEM");
        event.setLevel(AuditLevel.ERROR);
        event.setStatus(AuditStatus.FAILED);
        if (cert instanceof X509CertWithDbId) {
            Long certId = ((X509CertWithDbId) cert).certId();
            if (certId != null) {
                event.addEventData(CaAuditConstants.NAME_id, certId);
            }
        }
        event.addEventData(CaAuditConstants.NAME_issuer, issuer);
        event.addEventData(CaAuditConstants.NAME_subject, subjectText);
        event.addEventData(CaAuditConstants.NAME_serial, serialText);
        event.addEventData(CaAuditConstants.NAME_message, messagePrefix);
        auditServiceRegister.getAuditService().logEvent(event);
    } // method logAndAudit

    @Override
    public boolean crlAdded(final X509Cert caCert, final X509CRL crl) {
        return true;
    }

    @Override
    public boolean isHealthy() {
        return queryExecutor.isHealthy();
    }

    @Override
    public void setAuditServiceRegister(final AuditServiceRegister auditServiceRegister) {
        this.auditServiceRegister = ParamUtil.requireNonNull("auditServiceRegister",
                auditServiceRegister);
    }

    @Override
    public boolean caRevoked(final X509Cert caCert, final CertRevocationInfo revInfo) {
        try {
            queryExecutor.revokeCa(caCert, revInfo);
            return true;
        } catch (Exception ex) {
            String issuerText = X509Util.getRfc4519Name(caCert.cert().getIssuerX500Principal());
            logAndAudit(issuerText, caCert, ex, "could not publish revocation of CA");
            return false;
        }
    }

    @Override
    public boolean caUnrevoked(final X509Cert caCert) {
        try {
            queryExecutor.unrevokeCa(caCert);
            return true;
        } catch (Exception ex) {
            String issuerText = X509Util.getRfc4519Name(caCert.cert().getIssuerX500Principal());
            logAndAudit(issuerText, caCert, ex, "could not publish unrevocation of CA");
            return false;
        }
    }

    @Override
    public boolean certificateRemoved(final X509Cert issuerCert, final X509CertWithDbId cert) {
        try {
            queryExecutor.removeCert(issuerCert, cert);
            return true;
        } catch (Exception ex) {
            String issuerText = X509Util.getRfc4519Name(
                    issuerCert.cert().getIssuerX500Principal());
            logAndAudit(issuerText, issuerCert, ex, "could not publish removal of certificate");
            return false;
        }
    }

    @Override
    public boolean isAsyn() {
        return asyn;
    }

    @Override
    public boolean publishsGoodCert() {
        return publishsGoodCert;
    }

}
