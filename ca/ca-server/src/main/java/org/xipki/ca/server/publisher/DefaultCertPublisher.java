/*
 * Copyright (c) 2014 xipki.org
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
import org.xipki.database.api.DataSource;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.ParamChecker;

public class DefaultCertPublisher extends CertPublisher
{
    private static final Logger LOG = LoggerFactory.getLogger(DefaultCertPublisher.class);

    @SuppressWarnings("unused")
    private EnvironmentParameterResolver envParamterResolver;
    private CertStatusStoreQueryExecutor queryExecutor;
    private boolean publishGoodCerts = true;

    private AuditLoggingService auditLoggingService;

    public DefaultCertPublisher()
    {
    }

    @Override
    public void initialize(String conf, PasswordResolver passwordResolver,
            DataSource dataSource)
    throws CertPublisherException
    {
        ParamChecker.assertNotNull("conf", conf);
        ParamChecker.assertNotNull("dataSource", dataSource);

        CmpUtf8Pairs utf8pairs = new CmpUtf8Pairs(conf);
        String v = utf8pairs.getValue("publish.goodcerts");
        this.publishGoodCerts = (v == null) ? true : Boolean.parseBoolean(v);

        try
        {
            queryExecutor = new CertStatusStoreQueryExecutor(dataSource);
        } catch (NoSuchAlgorithmException e)
        {
            throw new CertPublisherException(e);
        } catch (SQLException e)
        {
            throw new CertPublisherException(e);
        }
    }

    @Override
    public void setEnvironmentParamterResolver(
            EnvironmentParameterResolver paramterResolver)
    {
        this.envParamterResolver = paramterResolver;
    }

    @Override
    public void certificateAdded(CertificateInfo certInfo)
    {
        X509CertificateWithMetaInfo caCert = certInfo.getIssuerCert();
        X509CertificateWithMetaInfo cert = certInfo.getCert();

        try
        {
            if(certInfo.isRevoked())
            {
                queryExecutor.addCert(caCert,
                        cert,
                        certInfo.getProfileName(),
                        certInfo.isRevoked(),
                        certInfo.getRevocationTime(),
                        certInfo.getRevocationReason(),
                        certInfo.getInvalidityTime());
            }
            else
            {
                if(publishGoodCerts)
                {
                    queryExecutor.addCert(caCert, cert, certInfo.getProfileName());
                }else
                {
                    queryExecutor.addIssuer(caCert);
                }
            }
        } catch (Exception e)
        {
            logAndAudit(caCert, cert, e, "could not save certificate");
        }
    }

    @Override
    public void certificateRevoked(X509CertificateWithMetaInfo caCert,
            X509CertificateWithMetaInfo cert,
            Date revocationTime,
            int revocationReason,
            Date invalidityTime)
    {
        try
        {
            queryExecutor.revokeCert(caCert, cert, revocationTime, revocationReason, invalidityTime);
        } catch (Exception e)
        {
            logAndAudit(caCert, cert, e, "could not publish revoked certificate");
        }
    }

    private void logAndAudit(X509CertificateWithMetaInfo caCert, X509CertificateWithMetaInfo cert, Exception e,
            String messagePrefix)
    {
        String issuerText = caCert.getSubject();
        String subjectText = cert.getSubject();
        String serialText = cert.getCert().getSerialNumber().toString();

        LOG.error("{} (issuser={}: subject={}, serialNumber={}). Message: {}",
                new Object[]{messagePrefix, issuerText, subjectText, serialText, e.getMessage()});
        LOG.debug("error", e);

        if(auditLoggingService != null)
        {
            AuditEvent auditEvent = new AuditEvent(new Date());
            auditEvent.setApplicationName("CAPublisher");
            auditEvent.setName("SYSTEM");
            auditEvent.setLevel(AuditLevel.ERROR);
            auditEvent.setStatus(AuditStatus.FAILED);
            auditEvent.addEventData(new AuditEventData("issuer", issuerText));
            auditEvent.addEventData(new AuditEventData("subject", subjectText));
            auditEvent.addEventData(new AuditEventData("issuer", serialText));
            auditEvent.addEventData(new AuditEventData("message", messagePrefix));
            auditLoggingService.logEvent(auditEvent);
        }
    }

    @Override
    public void crlAdded(X509CertificateWithMetaInfo cacert, X509CRL crl)
    {
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

}
