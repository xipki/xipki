/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.api.publisher.x509;

import java.security.cert.X509CRL;
import java.util.Map;

import org.xipki.audit.AuditServiceRegister;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.pki.ca.api.EnvParameterResolver;
import org.xipki.pki.ca.api.X509CertWithDbId;
import org.xipki.pki.ca.api.publisher.CertPublisherException;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class X509CertPublisher {

    /**
     *
     * @param conf
     *          Configuration. Could be {@code null}.
     * @param passwordResolver
     *          Password resolver. Could be {@code null}.
     * @param datasources
     *          Datasources. Must not be {@code null}.
     */
    public abstract void initialize(String conf, PasswordResolver passwordResolver,
            Map<String, DataSourceWrapper> datasources) throws CertPublisherException;

    public void shutdown() {
    }

    public abstract boolean publishsGoodCert();

    public abstract boolean isAsyn();

    /**
     *
     * @param parameterResolver
     *          Parameter resolver. Could be {@code null}.
     */
    public abstract void setEnvParameterResolver(EnvParameterResolver parameterResolver);

    /**
     *
     * @param caCert
     *          CA certificate to be published. Must not be {@code null}.
     * @return whether the CA is published.
     */
    public abstract boolean caAdded(X509Cert caCert);

    /**
     *
     * @param certInfo
     *          Certificate to be published.
     * @return whether the certificate is published.
     */
    public abstract boolean certificateAdded(X509CertificateInfo certInfo);

    /**
     *
     * @param caCert
     *          CA certificate. Must not be {@code null}.
     * @param cert
     *          Target certificate. Must not be {@code null}.
     * @param certprofile
     *          Certificate profile. Could be {@code null}.
     * @param revInfo
     *          Revocation information. Must not be {@code null}.
     * @return whether the revocation is published.
     */
    public abstract boolean certificateRevoked(X509Cert caCert,
            X509CertWithDbId cert, String certprofile, CertRevocationInfo revInfo);

    /**
     *
     * @param caCert
     *          CA certificate. Must not be {@code null}.
     * @param cert
     *          Target certificate. Must not be {@code null}.
     * @return whether the unrevocation is published.
     */
    public abstract boolean certificateUnrevoked(X509Cert caCert, X509CertWithDbId cert);

    /**
     *
     * @param caCert
     *          CA certificate. Must not be {@code null}.
     * @param cert
     *          Target certificate. Must not be {@code null}.
     * @return whether the remove is published.
     */
    public abstract boolean certificateRemoved(X509Cert caCert, X509CertWithDbId cert);

    /**
     *
     * @param caCert
     *          CA certificate. Must not be {@code null}.
     * @param crl
     *          CRL to be published. Must not be {@code null}.
     * @return whether the CRL is published.
     */
    public abstract boolean crlAdded(X509Cert caCert, X509CRL crl);

    /**
     *
     * @param caCert
     *          CA certificate. Must not be {@code null}.
     * @param revInfo
     *          Revocation information. Must not be {@code null}.
     * @return whether the CA revocation is published.
     */
    public abstract boolean caRevoked(X509Cert caCert, CertRevocationInfo revInfo);

    /**
     *
     * @param caCert
     *          CA certificate. Must not be {@code null}.
     * @return whether the CA unrevocation is published.
     */
    public abstract boolean caUnrevoked(X509Cert caCert);

    public abstract boolean isHealthy();

    /**
     *
     * @param auditServiceRegister
     *          AuditServiceRegister to be set. Must not be {@code null}.
     */
    public abstract void setAuditServiceRegister(AuditServiceRegister auditServiceRegister);

}
