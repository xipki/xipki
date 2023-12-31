// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.ca.api.CertificateInfo;
import org.xipki.security.HashAlgo;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;

import java.math.BigInteger;
import java.time.Clock;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * Pending certificate pool.
 *
 * @author Lijun Liao (xipki)
 * @since 5.3.4
 */

class PendingCertificatePool {

  private static class MyEntry {

    private final BigInteger certReqId;

    private final long waitForConfirmTill;

    private final CertificateInfo certInfo;

    private final byte[] certHash;

    MyEntry(BigInteger certReqId, long waitForConfirmTill, CertificateInfo certInfo) {
      this.certReqId = Args.notNull(certReqId, "certReqId");
      this.certInfo = Args.notNull(certInfo, "certInfo");
      this.waitForConfirmTill = waitForConfirmTill;
      this.certHash = HashAlgo.SHA1.hash(certInfo.getCert().getCert().getEncoded());
    } // constructor

    @Override
    public int hashCode() {
      return certReqId.hashCode() + 961 * (int) waitForConfirmTill + 31 * certInfo.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      } else if (!(obj instanceof PendingCertificatePool.MyEntry)) {
        return false;
      }

      PendingCertificatePool.MyEntry another = (PendingCertificatePool.MyEntry) obj;
      return certReqId.equals(another.certReqId) && certInfo.equals(another.certInfo);
    } // method equals

  } // class MyEntry

  private final Map<String, Set<PendingCertificatePool.MyEntry>> map = new HashMap<>();

  PendingCertificatePool() {
  }

  void addCertificate(String transactionId, BigInteger certReqId, CertificateInfo certInfo, long waitForConfirmTill) {
    Args.notNull(transactionId, "transactionId");
    if (Args.notNull(certInfo, "certInfo").isAlreadyIssued()) {
      return;
    }

    PendingCertificatePool.MyEntry myEntry = new MyEntry(certReqId, waitForConfirmTill, certInfo);
    synchronized (map) {
      Set<PendingCertificatePool.MyEntry> entries = map.computeIfAbsent(transactionId, k -> new HashSet<>());
      entries.add(myEntry);
    }
  } // method addCertificate

  CertificateInfo removeCertificate(String transactionId, BigInteger certReqId, byte[] certHash) {
    Args.notBlank(transactionId, "transactionId");
    Args.notNull(certReqId, "certReqId");
    Args.notNull(certHash, "certHash");

    PendingCertificatePool.MyEntry retEntry = null;

    synchronized (map) {
      Set<PendingCertificatePool.MyEntry> entries = map.get(transactionId);
      if (entries == null) {
        return null;
      }

      for (PendingCertificatePool.MyEntry entry : entries) {
        if (certReqId.equals(entry.certReqId)) {
          retEntry = entry;
          break;
        }
      }

      if (retEntry != null) {
        if (Arrays.equals(certHash, retEntry.certHash)) {
          entries.remove(retEntry);

          if (CollectionUtil.isEmpty(entries)) {
            map.remove(transactionId);
          }
        }
      }
    }

    return (retEntry == null) ? null : retEntry.certInfo;
  } // method removeCertificate

  Set<CertificateInfo> removeCertificates(String transactionId) {
    Args.notNull(transactionId, "transactionId");

    Set<PendingCertificatePool.MyEntry> entries;
    synchronized  (map) {
      entries = map.remove(transactionId);
    }

    if (entries == null) {
      return null;
    }

    Set<CertificateInfo> ret = new HashSet<>();
    for (PendingCertificatePool.MyEntry myEntry :entries) {
      ret.add(myEntry.certInfo);
    }
    return ret;
  } // method removeCertificates

  Set<CertificateInfo> removeConfirmTimeoutedCertificates() {
    synchronized (map) {
      if (CollectionUtil.isEmpty(map)) {
        return null;
      }

      long now = Clock.systemUTC().millis();

      Set<CertificateInfo> ret = new HashSet<>();

      for (Entry<String, Set<MyEntry>> entry0 : map.entrySet()) {
        Set<PendingCertificatePool.MyEntry> entries = entry0.getValue();
        for (PendingCertificatePool.MyEntry entry : entries) {
          if (entry.waitForConfirmTill < now) {
            ret.add(entry.certInfo);
          }
        }
      }
      return ret;
    }
  } // method removeConfirmTimeoutedCertificates

} // class PendingCertificatePool
