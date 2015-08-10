/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.ca.server.impl;

import java.security.cert.X509CRL;
import java.util.Map;

import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.ca.api.CertPublisherException;
import org.xipki.ca.api.EnvParameterResolver;
import org.xipki.ca.api.X509CertWithDBCertId;
import org.xipki.ca.api.publisher.X509CertPublisher;
import org.xipki.ca.api.publisher.X509CertificateInfo;
import org.xipki.ca.server.impl.publisher.OCSPCertPublisher;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.ParamChecker;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.password.api.PasswordResolver;

/**
 * @author Lijun Liao
 */

class IdentifiedX509CertPublisher
{
    private final PublisherEntry entry;
    private final X509CertPublisher certPublisher;

    public IdentifiedX509CertPublisher(
            final PublisherEntry entry,
            final String realType)
    throws CertPublisherException
    {
        ParamChecker.assertNotNull("entry", entry);

        this.entry = entry;

        final String type = realType == null ? entry.getType() : realType;

        X509CertPublisher realPublisher;
        if("ocsp".equalsIgnoreCase(type))
        {
            realPublisher = new OCSPCertPublisher();
        }
        else if(StringUtil.startsWithIgnoreCase(type, "java:"))
        {
            String className = type.substring("java:".length());
            try
            {
                Class<?> clazz = Class.forName(className);
                realPublisher = (X509CertPublisher) clazz.newInstance();
            }catch(Exception e)
            {
                throw new CertPublisherException("invalid type " + type + ", " + e.getMessage());
            }
        }
        else
        {
            throw new CertPublisherException("invalid type " + type);
        }
        this.certPublisher = realPublisher;
    }

    public void initialize(
            final PasswordResolver passwordResolver,
            final Map<String, DataSourceWrapper> dataSources)
    throws CertPublisherException
    {
        certPublisher.initialize(entry.getConf(), passwordResolver, dataSources);
    }

    public void setEnvParameterResolver(
            final EnvParameterResolver parameterResolver)
    {
        certPublisher.setEnvParameterResolver(parameterResolver);
    }

    public boolean issuerAdded(
            final X509CertWithDBCertId issuerCert)
    {
        return certPublisher.issuerAdded(issuerCert);
    }

    public boolean certificateAdded(
            final X509CertificateInfo certInfo)
    {
        return certPublisher.certificateAdded(certInfo);
    }

    public boolean certificateRevoked(
            final X509CertWithDBCertId issuerCert,
            final X509CertWithDBCertId cert,
            final String certprofile,
            final CertRevocationInfo revInfo)
    {
        return certPublisher.certificateRevoked(issuerCert, cert, certprofile, revInfo);
    }

    public boolean crlAdded(
            final X509CertWithDBCertId caCert,
            final X509CRL crl)
    {
        return certPublisher.crlAdded(caCert, crl);
    }

    public PublisherEntry getDbEntry()
    {
        return entry;
    }

    public String getName()
    {
        return entry.getName();
    }

    public boolean isHealthy()
    {
        return certPublisher.isHealthy();
    }

    public void setAuditServiceRegister(
            final AuditLoggingServiceRegister auditServiceRegister)
    {
        certPublisher.setAuditServiceRegister(auditServiceRegister);
    }

    public boolean caRevoked(
            final X509CertWithDBCertId caCert,
            final CertRevocationInfo revocationInfo)
    {
        return certPublisher.caRevoked(caCert, revocationInfo);
    }

    public boolean caUnrevoked(
            final X509CertWithDBCertId caCert)
    {
        return certPublisher.caUnrevoked(caCert);
    }

    public boolean certificateUnrevoked(
            final X509CertWithDBCertId issuerCert,
            final X509CertWithDBCertId cert)
    {
        return certPublisher.certificateUnrevoked(issuerCert, cert);
    }

    public boolean certificateRemoved(
            final X509CertWithDBCertId issuerCert,
            final X509CertWithDBCertId cert)
    {
        return certPublisher.certificateRemoved(issuerCert, cert);
    }

    public boolean isAsyn()
    {
        return certPublisher.isAsyn();
    }

    public void shutdown()
    {
        certPublisher.shutdown();
    }

    public boolean publishsGoodCert()
    {
        return certPublisher.publishsGoodCert();
    }

}
