/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
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
import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.audit.api.AuditStatus;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.CertPublisherException;
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

public class OCSPCertPublisher extends CertPublisher
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
