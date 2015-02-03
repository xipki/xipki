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

package org.xipki.ca.api.publisher;

import java.security.cert.X509CRL;
import java.util.Map;

import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.ca.api.CertPublisherException;
import org.xipki.ca.api.EnvironmentParameterResolver;
import org.xipki.ca.api.X509CertWithId;
import org.xipki.common.CertRevocationInfo;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.security.api.PasswordResolver;

/**
 * @author Lijun Liao
 */

public abstract class X509CertPublisher
{
    public abstract void initialize(String conf,
            PasswordResolver passwordResolver,
            Map<String, DataSourceWrapper> dataSources)
    throws CertPublisherException;

    public void shutdown()
    {
    }

    public abstract boolean publishsGoodCert();

    public abstract boolean isAsyn();

    public abstract void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver);

    public abstract boolean issuerAdded(X509CertWithId issuerCert);

    public abstract boolean certificateAdded(X509CertificateInfo certInfo);

    public abstract boolean certificateRevoked(X509CertWithId issuerCert,
            X509CertWithId cert,
            String certprofile,
            CertRevocationInfo revInfo);

    public abstract boolean certificateUnrevoked(X509CertWithId issuerCert,
            X509CertWithId cert);

    public abstract boolean certificateRemoved(X509CertWithId issuerCert,
            X509CertWithId cert);

    public abstract boolean crlAdded(X509CertWithId caCert, X509CRL crl);

    public abstract boolean caRevoked(X509CertWithId caCert, CertRevocationInfo revocationInfo);

    public abstract boolean caUnrevoked(X509CertWithId caCert);

    public abstract boolean isHealthy();

    public abstract void setAuditServiceRegister(AuditLoggingServiceRegister auditServiceRegister);
}
