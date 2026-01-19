// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.publisher;

import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;
import org.xipki.security.X509Crl;
import org.xipki.util.datasource.DataSourceMap;
import org.xipki.util.extra.exception.CertPublisherException;

import java.io.Closeable;

/**
 * Defines how to publish the certificates and CRLs. All CertPublisher classes
 * must extend this class.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class CertPublisher implements Closeable {

  protected CertPublisher() {
  }

  /**
   * Initializes me.
   *
   * @param conf
   *          Configuration. Could be {@code null}.
   * @param datasourceConfs
   *          Datasource name to configuration map. Must not be {@code null}.
   * @throws CertPublisherException
   *         If error during the initialization occurs.
   */
  public abstract void initialize(String conf, DataSourceMap datasourceConfs)
      throws CertPublisherException;

  @Override
  public void close() {
  }

  public abstract boolean publishsGoodCert();

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
  public abstract boolean certificateAdded(CertificateInfo certInfo);

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
  public abstract boolean certificateRevoked(
      X509Cert caCert, CertWithDbId cert, String certprofile,
      CertRevocationInfo revInfo);

  /**
   * Publishes the unrevocation of a certificate.
   *
   * @param caCert
   *          CA certificate. Must not be {@code null}.
   * @param cert
   *          Target certificate. Must not be {@code null}.
   * @return whether the unrevocation is published.
   */
  public abstract boolean certificateUnrevoked(
      X509Cert caCert, CertWithDbId cert);

  /**
   * Publishes the remove of a certificate.
   *
   * @param caCert
   *          CA certificate. Must not be {@code null}.
   * @param cert
   *          Target certificate. Must not be {@code null}.
   * @return whether the remove is published.
   */
  public abstract boolean certificateRemoved(
      X509Cert caCert, CertWithDbId cert);

  /**
   * Publishes a CRL.
   *
   * @param caCert
   *          CA certificate. Must not be {@code null}.
   * @param crl
   *          CRL to be published. Must not be {@code null}.
   * @return whether the CRL is published.
   */
  public abstract boolean crlAdded(X509Cert caCert, X509Crl crl);

  /**
   * Publishes the revocation of a CA.
   *
   * @param caCert
   *          CA certificate. Must not be {@code null}.
   * @param revInfo
   *          Revocation information. Must not be {@code null}.
   * @return whether the CA revocation is published.
   */
  public abstract boolean caRevoked(
      X509Cert caCert, CertRevocationInfo revInfo);

  /**
   * Publishes the unrevocation of a CA.
   *
   * @param caCert
   *          CA certificate. Must not be {@code null}.
   * @return whether the CA unrevocation is published.
   */
  public abstract boolean caUnrevoked(X509Cert caCert);

  public abstract boolean isHealthy();

}
