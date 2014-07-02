/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.publisher;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509CRL;
import java.sql.SQLException;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.audit.api.AuditStatus;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class DefaultCertPublisher extends CertPublisher
{
    private static final Logger LOG = LoggerFactory.getLogger(DefaultCertPublisher.class);

    @SuppressWarnings("unused")
    private EnvironmentParameterResolver envParameterResolver;
    private CertStatusStoreQueryExecutor queryExecutor;
    private boolean asyn = false;

    private AuditLoggingService auditLoggingService;

    public DefaultCertPublisher()
    {
    }

    @Override
    public void initialize(String conf, PasswordResolver passwordResolver, DataSourceWrapper dataSource)
    throws CertPublisherException
    {
        ParamChecker.assertNotNull("conf", conf);
        ParamChecker.assertNotNull("dataSource", dataSource);

        CmpUtf8Pairs utf8pairs = new CmpUtf8Pairs(conf);
        String v = utf8pairs.getValue("publish.goodcerts");
        boolean publishGoodCerts = (v == null) ? true : Boolean.parseBoolean(v);

        v = utf8pairs.getValue("asyn");
        this.asyn = (v == null) ? false : Boolean.parseBoolean(v);

        try
        {
            queryExecutor = new CertStatusStoreQueryExecutor(dataSource, publishGoodCerts);
        } catch (NoSuchAlgorithmException e)
        {
            throw new CertPublisherException(e);
        } catch (SQLException e)
        {
            throw new CertPublisherException(e);
        }
    }

    @Override
    public void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver)
    {
        this.envParameterResolver = parameterResolver;
    }

    @Override
    public boolean certificateAdded(CertificateInfo certInfo)
    {
        X509CertificateWithMetaInfo caCert = certInfo.getIssuerCert();
        X509CertificateWithMetaInfo cert = certInfo.getCert();

        try
        {
            queryExecutor.addCert(caCert, cert, certInfo.getProfileName(), certInfo.getRevocationInfo());
            return true;
        } catch (Exception e)
        {
            logAndAudit(caCert.getSubject(), cert, e, "could not save certificate");
            return false;
        }
    }

    @Override
    public boolean certificateRevoked(X509CertificateWithMetaInfo caCert,
            X509CertificateWithMetaInfo cert,
            CertRevocationInfo revInfo)
    {
        try
        {
            queryExecutor.revokeCert(caCert, cert, revInfo);
            return true;
        } catch (Exception e)
        {
            logAndAudit(caCert.getSubject(), cert, e, "could not publish revoked certificate");
            return false;
        }
    }

    @Override
    public boolean certificateUnrevoked(X509CertificateWithMetaInfo caCert,
            X509CertificateWithMetaInfo cert)
    {
        try
        {
            queryExecutor.unrevokeCert(caCert, cert);
            return true;
        } catch (Exception e)
        {
            logAndAudit(caCert.getSubject(), cert, e, "could not publish unrevocation of certificate");
            return false;
        }
    }

    private void logAndAudit(String issuer, X509CertificateWithMetaInfo cert, Exception e,
            String messagePrefix)
    {
        String subjectText = cert.getSubject();
        String serialText = cert.getCert().getSerialNumber().toString();

        LOG.error("{} (issuser={}: subject={}, serialNumber={}). Message: {}",
                new Object[]{messagePrefix, issuer, subjectText, serialText, e.getMessage()});
        LOG.debug("error", e);

        if(auditLoggingService != null)
        {
            AuditEvent auditEvent = new AuditEvent(new Date());
            auditEvent.setApplicationName("CAPublisher");
            auditEvent.setName("SYSTEM");
            auditEvent.setLevel(AuditLevel.ERROR);
            auditEvent.setStatus(AuditStatus.FAILED);
            auditEvent.addEventData(new AuditEventData("issuer", issuer));
            auditEvent.addEventData(new AuditEventData("subject", subjectText));
            auditEvent.addEventData(new AuditEventData("serialNumber", serialText));
            auditEvent.addEventData(new AuditEventData("message", messagePrefix));
            auditLoggingService.logEvent(auditEvent);
        }
    }

    @Override
    public boolean crlAdded(X509CertificateWithMetaInfo caCert, X509CRL crl)
    {
        return true;
    }

    @Override
    public boolean isHealthy()
    {
        return queryExecutor.isHealthy();
    }

    @Override
    public void setAuditLoggingService(AuditLoggingService auditLoggingService)
    {
        this.auditLoggingService = auditLoggingService;
    }

    @Override
    public boolean caRevoked(X509CertificateWithMetaInfo caCert, CertRevocationInfo revocationInfo)
    {
        try
        {
            queryExecutor.revokeCa(caCert, revocationInfo);
            return true;
        } catch (Exception e)
        {
            String issuerText = IoCertUtil.canonicalizeName(caCert.getCert().getIssuerX500Principal());
            logAndAudit(issuerText, caCert, e, "Could not publish revocation of CA");
            return false;
        }
    }

    @Override
    public boolean caUnrevoked(X509CertificateWithMetaInfo caCert)
    {
        try
        {
            queryExecutor.unrevokeCa(caCert);
            return true;
        } catch (Exception e)
        {
            String issuerText = IoCertUtil.canonicalizeName(caCert.getCert().getIssuerX500Principal());
            logAndAudit(issuerText, caCert, e, "Could not publish unrevocation of CA");
            return false;
        }
    }

    @Override
    public boolean certificateRemoved(X509CertificateWithMetaInfo issuerCert,
            X509CertificateWithMetaInfo cert)
    {
        try
        {
            queryExecutor.removeCert(issuerCert, cert);
            return true;
        } catch (Exception e)
        {
            String issuerText = IoCertUtil.canonicalizeName(issuerCert.getCert().getIssuerX500Principal());
            logAndAudit(issuerText, issuerCert, e, "Could not publish removal of certificate");
            return false;
        }
    }

    @Override
    public boolean isAsyn()
    {
        return asyn;
    }

}
