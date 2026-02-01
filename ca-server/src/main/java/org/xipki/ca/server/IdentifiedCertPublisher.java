// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;
import org.xipki.security.X509Crl;
import org.xipki.util.codec.Args;
import org.xipki.util.datasource.DataSourceMap;
import org.xipki.util.extra.exception.CertPublisherException;

import java.io.Closeable;

/**
 * CertPublisher with identifier.
 *
 * @author Lijun Liao (xipki)
 */

public class IdentifiedCertPublisher implements Closeable {

  private final PublisherEntry entry;

  private final CertPublisher certPublisher;

  public IdentifiedCertPublisher(PublisherEntry entry,
                                 CertPublisher certPublisher) {
    this.entry = Args.notNull(entry, "entry");
    this.certPublisher = Args.notNull(certPublisher, "certPublisher");
  }

  public void initialize(DataSourceMap datasourceConfs)
      throws CertPublisherException {
    certPublisher.initialize(entry.conf(), datasourceConfs);
  }

  public boolean caAdded(X509Cert caCert) {
    return certPublisher.caAdded(caCert);
  }

  public boolean certificateAdded(CertificateInfo certInfo) {
    return certPublisher.certificateAdded(certInfo);
  }

  public boolean certificateRevoked(
      X509Cert caCert, CertWithDbId cert, String certprofile,
      CertRevocationInfo revInfo) {
    return certPublisher.certificateRevoked(caCert, cert, certprofile, revInfo);
  }

  public boolean crlAdded(X509Cert caCert, X509Crl crl) {
    return certPublisher.crlAdded(caCert, crl);
  }

  public PublisherEntry dbEntry() {
    return entry;
  }

  public NameId ident() {
    return entry.ident();
  }

  public boolean isHealthy() {
    return certPublisher.isHealthy();
  }

  public boolean caRevoked(X509Cert caCert, CertRevocationInfo revocationInfo) {
    return certPublisher.caRevoked(caCert, revocationInfo);
  }

  public boolean caUnrevoked(X509Cert caCert) {
    return certPublisher.caUnrevoked(caCert);
  }

  public boolean certificateUnrevoked(X509Cert caCert, CertWithDbId cert) {
    return certPublisher.certificateUnrevoked(caCert, cert);
  }

  public boolean certificateRemoved(X509Cert caCert, CertWithDbId cert) {
    return certPublisher.certificateRemoved(caCert, cert);
  }

  @Override
  public void close() {
    certPublisher.close();
  }

  public boolean publishsGoodCert() {
    return certPublisher.publishsGoodCert();
  }

}
