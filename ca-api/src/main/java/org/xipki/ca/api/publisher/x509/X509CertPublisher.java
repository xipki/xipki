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

package org.xipki.ca.api.publisher.x509;

import java.security.cert.X509CRL;
import java.util.Map;

import org.xipki.audit.AuditServiceRegister;
import org.xipki.ca.api.EnvParameterResolver;
import org.xipki.ca.api.X509CertWithDbId;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class X509CertPublisher {

    /**
     * Initializes me.
     *
     * @param conf
     *          Configuration. Could be {@code null}.
     * @param passwordResolver
     *          Password resolver. Could be {@code null}.
     * @param datasources
     *          Datasources. Must not be {@code null}.
     * @throws CertPublisherException
     *         If error during the initialization occurs.
     */
    public abstract void initialize(String conf, PasswordResolver passwordResolver,
            Map<String, DataSourceWrapper> datasources) throws CertPublisherException;

    public void shutdown() {
    }

    public abstract boolean publishsGoodCert();

    public abstract boolean isAsyn();

    /**
     * Sets the {{@link EnvParameterResolver}.
     *
     * @param parameterResolver
     *          Parameter resolver. Could be {@code null}.
     */
    public abstract void setEnvParameterResolver(EnvParameterResolver parameterResolver);

    /**
     * Publishes the certificate of the CA.
     * @param caCert
     *          CA certificate to be published. Must not be {@code null}.
     * @return whether the CA is published.
     */
    public abstract boolean caAdded(X509Cert caCert);

    /**
     * Publishes a certificate.
     *
     * @param certInfo
     *          Certificate to be published.
     * @return whether the certificate is published.
     */
    public abstract boolean certificateAdded(X509CertificateInfo certInfo);

    /**
     * Publishes the revocation of a certificate.
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
     * Publishes the unrevocation of a certificate.
     *
     * @param caCert
     *          CA certificate. Must not be {@code null}.
     * @param cert
     *          Target certificate. Must not be {@code null}.
     * @return whether the unrevocation is published.
     */
    public abstract boolean certificateUnrevoked(X509Cert caCert, X509CertWithDbId cert);

    /**
     * Publishes the remove of a certificate.
     *
     * @param caCert
     *          CA certificate. Must not be {@code null}.
     * @param cert
     *          Target certificate. Must not be {@code null}.
     * @return whether the remove is published.
     */
    public abstract boolean certificateRemoved(X509Cert caCert, X509CertWithDbId cert);

    /**
     * Publishes a CRL.
     *
     * @param caCert
     *          CA certificate. Must not be {@code null}.
     * @param crl
     *          CRL to be published. Must not be {@code null}.
     * @return whether the CRL is published.
     */
    public abstract boolean crlAdded(X509Cert caCert, X509CRL crl);

    /**
     * Publishes the revocation of a CA.
     *
     * @param caCert
     *          CA certificate. Must not be {@code null}.
     * @param revInfo
     *          Revocation information. Must not be {@code null}.
     * @return whether the CA revocation is published.
     */
    public abstract boolean caRevoked(X509Cert caCert, CertRevocationInfo revInfo);

    /**
     * Publishes the unrevocation of a CA.
     *
     * @param caCert
     *          CA certificate. Must not be {@code null}.
     * @return whether the CA unrevocation is published.
     */
    public abstract boolean caUnrevoked(X509Cert caCert);

    public abstract boolean isHealthy();

    /**
     * Sets the AuditServiceRegister.
     *
     * @param auditServiceRegister
     *          AuditServiceRegister to be set. Must not be {@code null}.
     */
    public abstract void setAuditServiceRegister(AuditServiceRegister auditServiceRegister);

}
