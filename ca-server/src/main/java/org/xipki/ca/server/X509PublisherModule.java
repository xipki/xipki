// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.bouncycastle.cert.X509CRLHolder;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;

import java.util.ArrayList;
import java.util.List;

/**
 * X509CA publisher module.
 *
 * @author Lijun Liao (xipki)
 */

class X509PublisherModule extends X509CaModule {

  private final CertStore certstore;

  private final CaIdNameMap caIdNameMap;

  private final CaManagerImpl caManager;

  X509PublisherModule(CaManagerImpl caManager, CaInfo caInfo, CertStore certstore) {
    super(caInfo);

    this.caManager = Args.notNull(caManager, "caManager");
    this.caIdNameMap = caManager.idNameMap();
    this.certstore = Args.notNull(certstore, "certstore");

    for (IdentifiedCertPublisher publisher : publishers()) {
      publisher.caAdded(caCert);
    }
  } // constructor

  /**
   * Publish certificate.
   *
   * @param certInfo certificate to be published.
   * @return 0: for published successfully, 1: if could not be published to CA certstore and
   *     any publishers, 2: if could be published to CA certstore but not to all publishers.
   */
  int publishCert(CertificateInfo certInfo, boolean saveKeypair) {
    if (Args.notNull(certInfo, "certInfo").isAlreadyIssued()) {
      return 0;
    }

    if (!certstore.addCert(certInfo, saveKeypair)) {
      return 1;
    }

    List<String> failedPublishers = null;

    for (IdentifiedCertPublisher publisher : publishers()) {
      boolean successful;
      try {
        successful = publisher.certificateAdded(certInfo);
      } catch (RuntimeException ex) {
        successful = false;
      }

      if (!successful) {
        if (failedPublishers == null) {
          failedPublishers = new ArrayList<>(1);
        }
        failedPublishers.add(publisher.getIdent().getName());
      }
    } // end for

    if (failedPublishers == null) {
      return 0;
    }

    if (LOG.isWarnEnabled()) {
      LOG.warn("could not publish to publishers {}: {}", failedPublishers,
          Base64.encodeToString(certInfo.getCert().getCert().getEncoded(), true));
    }
    return 2;
  } // method publishCert0

  boolean republishCerts(List<String> publisherNames, int numThreads) {
    List<IdentifiedCertPublisher> publishers;
    if (publisherNames == null) {
      publishers = publishers();
    } else {
      publishers = new ArrayList<>(publisherNames.size());

      for (String publisherName : publisherNames) {
        IdentifiedCertPublisher publisher = null;
        for (IdentifiedCertPublisher p : publishers()) {
          if (p.getIdent().getName().equals(publisherName)) {
            publisher = p;
            break;
          }
        }

        if (publisher == null) {
          throw new IllegalArgumentException(
              "could not find publisher " + publisherName + " for CA " + caIdent.getName());
        }
        publishers.add(publisher);
      }
    } // end if

    if (CollectionUtil.isEmpty(publishers)) {
      return true;
    }

    CaStatus status = caInfo.getStatus();

    caInfo.setStatus(CaStatus.inactive);

    boolean onlyRevokedCerts = true;
    for (IdentifiedCertPublisher publisher : publishers) {
      if (publisher.publishsGoodCert()) {
        onlyRevokedCerts = false;
        break;
      }
    } // end for

    try {
      for (IdentifiedCertPublisher publisher : publishers) {
        boolean successful = publisher.caAdded(caCert);
        if (!successful) {
          LOG.error("republish CA certificate {} to publisher {} failed", caIdent.getName(),
              publisher.getIdent().getName());
          return false;
        }
      }

      if (caInfo.getRevocationInfo() != null) {
        for (IdentifiedCertPublisher publisher : publishers) {
          boolean successful = publisher.caRevoked(caCert, caInfo.getRevocationInfo());
          if (!successful) {
            LOG.error("republishing CA revocation to publisher {} failed", publisher.getIdent().getName());
            return false;
          }
        }
      } // end if

      CertRepublisher republisher = new CertRepublisher(caIdent, caCert,
          caIdNameMap, certstore, publishers, onlyRevokedCerts, numThreads);
      return republisher.republish();
    } finally {
      caInfo.setStatus(status);
    }
  } // method republishCerts

  void publishCrl(X509CRLHolder crl) {
    try {
      certstore.addCrl(caIdent, crl);
    } catch (Exception ex) {
      LOG.error("could not add CRL ca={}, thisUpdate={}: {}, ",
          caIdent.getName(), crl.getThisUpdate(), ex.getMessage());
      LOG.debug("Exception", ex);
      return;
    }

    for (IdentifiedCertPublisher publisher : publishers()) {
      try {
        publisher.crlAdded(caCert, crl);
      } catch (RuntimeException ex) {
        LogUtil.error(LOG, ex, "could not publish CRL to the publisher " + publisher.getIdent());
      }
    } // end for
  } // method publishCrl

  boolean publishCertRemoved(CertWithDbId certToRemove) {
    boolean successful = true;
    for (IdentifiedCertPublisher publisher : publishers()) {
      boolean singleSuccessful;
      try {
        singleSuccessful = publisher.certificateRemoved(caCert, certToRemove);
      } catch (RuntimeException ex) {
        singleSuccessful = false;
        LogUtil.warn(LOG, ex, "could not remove certificate from the publisher " + publisher.getIdent());
      }

      if (singleSuccessful) {
        continue;
      }

      successful = false;
      X509Cert cert = certToRemove.getCert();
      if (LOG.isErrorEnabled()) {
        LOG.error("removing certificate issuer='{}', serial={}, subject='{}' from publisher"
            + " {} failed.", cert.getIssuerText(), cert.getSerialNumberHex(),
            cert.getSubjectText(), publisher.getIdent());
      }
    } // end for

    return successful;
  }

  void publishCertRevoked(CertWithRevocationInfo revokedCert) {
    for (IdentifiedCertPublisher publisher : publishers()) {
      boolean successful;
      try {
        successful = publisher.certificateRevoked(caCert, revokedCert.getCert(),
                revokedCert.getCertprofile(), revokedCert.getRevInfo());
      } catch (RuntimeException ex) {
        successful = false;
      }

      if (!successful) {
        LOG.error("could not publish revocation of certificate to the publisher {}", publisher.getIdent());
      }
    } // end for
  }

  void publishCertUnrevoked(CertWithDbId unrevokedCert) {
    List<String> failedPublishers = null;
    for (IdentifiedCertPublisher publisher : publishers()) {
      boolean successful;
      try {
        successful = publisher.certificateUnrevoked(caCert, unrevokedCert);
      } catch (RuntimeException ex) {
        successful = false;
      }

      if (!successful) {
        if (failedPublishers == null) {
          failedPublishers = new ArrayList<>(1);
        }
        failedPublishers.add(publisher.getIdent().getName());
      }
    } // end for

    if (failedPublishers == null) {
      return;
    }

    LOG.error("could not publishCertUnrevoked of certificate {} to publishers {}",
        unrevokedCert.getCertId(), failedPublishers);
  }

  boolean publishCaRevoked(CertRevocationInfo revocationInfo) {
    boolean succ = true;
    for (IdentifiedCertPublisher publisher : publishers()) {
      NameId ident = publisher.getIdent();
      boolean successful = publisher.caRevoked(caCert, revocationInfo);
      if (successful) {
        LOG.info("published event caRevoked of CA {} to publisher {}", caIdent.getName(), ident.getName());
      } else {
        succ = false;
        LOG.error("could not publish event caRevoked of CA {} to publisher {}", caIdent.getName(), ident.getName());
      }
    }

    return succ;
  }

  boolean publishCaUnrevoked() {
    boolean succ = true;
    for (IdentifiedCertPublisher publisher : publishers()) {
      NameId ident = publisher.getIdent();
      boolean successful = publisher.caUnrevoked(caCert);
      if (successful) {
        LOG.info("published event caUnrevoked of CA {} to publisher {}", caIdent.getName(), ident.getName());
      } else {
        succ = false;
        LOG.error("could not publish event caUnrevoked of CA {} to publisher {}", caIdent.getName(), ident.getName());
      }
    }

    return succ;
  }

  private List<IdentifiedCertPublisher> publishers() {
    return caManager.getIdentifiedPublishersForCa(caIdent.getName());
  }

}
