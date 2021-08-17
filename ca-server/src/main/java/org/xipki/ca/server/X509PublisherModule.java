/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.server;

import org.bouncycastle.cert.X509CRLHolder;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.server.db.CertStore;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;
import org.xipki.util.CollectionUtil;
import org.xipki.util.HealthCheckResult;
import org.xipki.util.LogUtil;

import java.util.ArrayList;
import java.util.List;

import static org.xipki.util.Args.notNull;

/**
 * X509CA publisher module.
 *
 * @author Lijun Liao
 */

class X509PublisherModule extends X509CaModule {

  private final CertStore certstore;

  private final CaIdNameMap caIdNameMap;

  private final CaManagerImpl caManager;

  X509PublisherModule(CaManagerImpl caManager, CaInfo caInfo, CertStore certstore) {
    super(caInfo);

    this.caManager = notNull(caManager, "caManager");
    this.caIdNameMap = caManager.idNameMap();
    this.certstore = notNull(certstore, "certstore");

    for (IdentifiedCertPublisher publisher : publishers()) {
      publisher.caAdded(caCert);
    }
  } // constructor

  /**
   * Publish certificate.
   *
   * @param certInfo certificate to be published.
   * @return 0 for published successfully, 1 if could not be published to CA certstore and
   *     any publishers, 2 if could be published to CA certstore but not to all publishers.
   */
  int publishCert(CertificateInfo certInfo) {
    notNull(certInfo, "certInfo");
    if (certInfo.isAlreadyIssued()) {
      return 0;
    }

    if (!certstore.addCert(certInfo)) {
      return 1;
    }

    for (IdentifiedCertPublisher publisher : publishers()) {
      boolean successful;
      try {
        successful = publisher.certificateAdded(certInfo);
      } catch (RuntimeException ex) {
        successful = false;
        LogUtil.warn(LOG, ex, "could not publish certificate to the publisher "
                + publisher.getIdent());
      }

      if (successful) {
        continue;
      }

      Long certId = certInfo.getCert().getCertId();
      try {
        certstore.addToPublishQueue(publisher.getIdent(), certId, caIdent);
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not add entry to PublishQueue");
        return 2;
      }
    } // end for

    return 0;
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

    caInfo.setStatus(CaStatus.INACTIVE);

    boolean onlyRevokedCerts = true;
    for (IdentifiedCertPublisher publisher : publishers) {
      if (publisher.publishsGoodCert()) {
        onlyRevokedCerts = false;
      }

      NameId publisherIdent = publisher.getIdent();
      String name = publisherIdent.getName();
      try {
        LOG.info("clearing PublishQueue for publisher {}", name);
        certstore.clearPublishQueue(caIdent, publisherIdent);
        LOG.info(" cleared PublishQueue for publisher {}", name);
      } catch (OperationException ex) {
        LogUtil.error(LOG, ex, "could not clear PublishQueue for publisher " + name);
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
            LOG.error("republishing CA revocation to publisher {} failed",
                publisher.getIdent().getName());
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

  void clearPublishQueue(List<String> publisherNames) throws CaMgmtException {
    if (publisherNames == null) {
      try {
        certstore.clearPublishQueue(caIdent, null);
      } catch (OperationException ex) {
        throw new CaMgmtException(
            "could not clear publish queue of CA " + caIdent + ": " + ex.getMessage(), ex);
      }

      return;
    }

    for (String publisherName : publisherNames) {
      NameId publisherIdent = caIdNameMap.getPublisher(publisherName);
      try {
        certstore.clearPublishQueue(caIdent, publisherIdent);
      } catch (OperationException ex) {
        throw new CaMgmtException(
            "could not clear publish queue of CA " + caIdent + ": " + ex.getMessage()
            + " for publisher " + publisherName, ex);
      }
    }
  } // method clearPublishQueue

  boolean publishCertsInQueue() {
    boolean allSuccessful = true;
    for (IdentifiedCertPublisher publisher : publishers()) {
      if (!publishCertsInQueue(publisher)) {
        allSuccessful = false;
      }
    }

    return allSuccessful;
  }

  boolean publishCertsInQueue(IdentifiedCertPublisher publisher) {
    notNull(publisher, "publisher");
    final int numEntries = 500;

    while (true) {
      List<Long> certIds;
      try {
        certIds = certstore.getPublishQueueEntries(caIdent, publisher.getIdent(), numEntries);
      } catch (OperationException ex) {
        LogUtil.error(LOG, ex);
        return false;
      }

      if (CollectionUtil.isEmpty(certIds)) {
        break;
      }

      for (Long certId : certIds) {
        CertificateInfo certInfo;

        try {
          certInfo = certstore.getCertForId(caIdent, caCert, certId, caIdNameMap);
        } catch (OperationException ex) {
          LogUtil.error(LOG, ex);
          return false;
        }

        boolean successful = publisher.certificateAdded(certInfo);
        if (!successful) {
          LOG.error("republishing certificate id={} failed", certId);
          return false;
        }

        try {
          certstore.removeFromPublishQueue(publisher.getIdent(), certId);
        } catch (OperationException ex) {
          LogUtil.warn(LOG, ex, "could not remove republished cert id=" + certId
              + " and publisher=" + publisher.getIdent().getName());
        }
      } // end for
    } // end while

    return true;
  } // method publishCertsInQueue

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
        LogUtil.warn(LOG, ex,
            "could not remove certificate from the publisher " + publisher.getIdent());
      }

      if (singleSuccessful) {
        continue;
      }

      successful = false;
      X509Cert cert = certToRemove.getCert();
      if (LOG.isErrorEnabled()) {
        LOG.error("removing certificate issuer='{}', serial={}, subject='{}' from publisher"
            + " {} failed.", cert.getIssuerRfc4519Text(), cert.getSerialNumberHex(),
            cert.getSubjectRfc4519Text(), publisher.getIdent());
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
        LogUtil.error(LOG, ex, "could not publish revocation of certificate to the publisher "
                + publisher.getIdent());
      }

      if (successful) {
        continue;
      }

      Long certId = revokedCert.getCert().getCertId();
      try {
        certstore.addToPublishQueue(publisher.getIdent(), certId, caIdent);
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not add entry to PublishQueue");
      }
    } // end for
  }

  void publishCertUnrevoked(CertWithDbId unrevokedCert) {
    for (IdentifiedCertPublisher publisher : publishers()) {
      boolean successful;
      try {
        successful = publisher.certificateUnrevoked(caCert, unrevokedCert);
      } catch (RuntimeException ex) {
        successful = false;
        LogUtil.error(LOG, ex, "could not publish unrevocation of certificate to the publisher "
                + publisher.getIdent().getName());
      }

      if (successful) {
        continue;
      }

      Long certId = unrevokedCert.getCertId();
      try {
        certstore.addToPublishQueue(publisher.getIdent(), certId, caIdent);
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not add entry to PublishQueue");
      }
    }
  }

  boolean publishCaRevoked(CertRevocationInfo revocationInfo) {
    boolean succ = true;
    for (IdentifiedCertPublisher publisher : publishers()) {
      NameId ident = publisher.getIdent();
      boolean successful = publisher.caRevoked(caCert, revocationInfo);
      if (successful) {
        LOG.info("published event caUnrevoked of CA {} to publisher {}",
            caIdent.getName(), ident.getName());
      } else {
        succ = false;
        LOG.error("could not publish event caUnrevoked of CA {} to publisher {}",
            caIdent.getName(), ident.getName());
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
        LOG.info("published event caUnrevoked of CA {} to publisher {}",
            caIdent.getName(), ident.getName());
      } else {
        succ = false;
        LOG.error("could not publish event caUnrevoked of CA {} to publisher {}",
            caIdent.getName(), ident.getName());
      }
    }

    return succ;
  }

  boolean healthCheck(HealthCheckResult parentResult) {
    boolean healthy = true;
    for (IdentifiedCertPublisher publisher : publishers()) {
      boolean ph = publisher.isHealthy();
      healthy &= ph;

      HealthCheckResult publisherHealth = new HealthCheckResult();
      publisherHealth.setName("Publisher");
      publisherHealth.setHealthy(publisher.isHealthy());
      parentResult.addChildCheck(publisherHealth);
    }
    return healthy;
  }

  private List<IdentifiedCertPublisher> publishers() {
    return caManager.getIdentifiedPublishersForCa(caIdent.getName());
  }

}
