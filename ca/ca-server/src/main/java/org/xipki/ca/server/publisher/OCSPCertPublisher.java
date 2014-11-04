/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
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
import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.audit.api.AuditStatus;
import org.xipki.ca.api.publisher.X509CertPublisher;
import org.xipki.ca.api.publisher.X509CertificateInfo;
import org.xipki.ca.common.CertPublisherException;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.EnvironmentParameterResolver;
import org.xipki.common.IoCertUtil;
import org.xipki.common.ParamChecker;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.security.api.PasswordResolver;

/**
 * @author Lijun Liao
 */

public class OCSPCertPublisher extends X509CertPublisher
{
    private static final Logger LOG = LoggerFactory.getLogger(OCSPCertPublisher.class);

    @SuppressWarnings("unused")
    private EnvironmentParameterResolver envParameterResolver;
    private OCSPStoreQueryExecutor queryExecutor;
    private boolean asyn = false;
    private boolean publishsGoodCert = true;

    private AuditLoggingServiceRegister auditServiceRegister;

    public OCSPCertPublisher()
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
        this.publishsGoodCert = (v == null) ? true : Boolean.parseBoolean(v);

        v = utf8pairs.getValue("asyn");
        this.asyn = (v == null) ? false : Boolean.parseBoolean(v);

        try
        {
            queryExecutor = new OCSPStoreQueryExecutor(dataSource, this.publishsGoodCert);
        } catch (NoSuchAlgorithmException | SQLException e)
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
    public boolean issuerAdded(X509CertificateWithMetaInfo issuer)
    {
        try
        {
            queryExecutor.addIssuer(issuer);
            return true;
        } catch (Exception e)
        {
            logAndAudit(issuer.getSubject(), issuer, e, "could not publish issuer");
            return false;
        }
    }

    @Override
    public boolean certificateAdded(X509CertificateInfo certInfo)
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

        AuditLoggingService auditLoggingService = auditServiceRegister == null ? null :
            auditServiceRegister.getAuditLoggingService();

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
    public void setAuditServiceRegister(AuditLoggingServiceRegister auditServiceRegister)
    {
        this.auditServiceRegister = auditServiceRegister;
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

    @Override
    public boolean publishsGoodCert()
    {
        return publishsGoodCert;
    }

}
