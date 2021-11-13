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

package org.xipki.ca.server.cmp;

import org.xipki.ca.api.CertificateInfo;
import org.xipki.security.HashAlgo;
import org.xipki.util.CollectionUtil;
import org.xipki.util.Hex;

import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;

import static org.xipki.util.Args.notNull;

/**
 * Pending certificate pool.
 *
 * @author Lijun Liao
 * @since 5.3.4
 */

class PendingCertificatePool {

  private static class MyEntry {

    private final BigInteger certReqId;

    private final long waitForConfirmTill;

    private final CertificateInfo certInfo;

    private final byte[] certHash;

    MyEntry(BigInteger certReqId, long waitForConfirmTill, CertificateInfo certInfo) {
      this.certReqId = notNull(certReqId, "certReqId");
      this.certInfo = notNull(certInfo, "certInfo");
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

  void addCertificate(byte[] transactionId, BigInteger certReqId, CertificateInfo certInfo,
      long waitForConfirmTill) {
    notNull(transactionId, "transactionId");
    notNull(certInfo, "certInfo");
    if (certInfo.isAlreadyIssued()) {
      return;
    }

    String hexTid = Hex.encode(transactionId);
    PendingCertificatePool.MyEntry myEntry = new MyEntry(certReqId, waitForConfirmTill, certInfo);
    synchronized (map) {
      Set<PendingCertificatePool.MyEntry> entries =
              map.computeIfAbsent(hexTid, k -> new HashSet<>());
      entries.add(myEntry);
    }
  } // method addCertificate

  CertificateInfo removeCertificate(byte[] transactionId, BigInteger certReqId, byte[] certHash) {
    notNull(transactionId, "transactionId");
    notNull(certReqId, "certReqId");
    notNull(certHash, "certHash");

    String hexTid = Hex.encode(transactionId);
    PendingCertificatePool.MyEntry retEntry = null;

    synchronized (map) {
      Set<PendingCertificatePool.MyEntry> entries = map.get(hexTid);
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
            map.remove(hexTid);
          }
        }
      }
    }

    return (retEntry == null) ? null : retEntry.certInfo;
  } // method removeCertificate

  Set<CertificateInfo> removeCertificates(byte[] transactionId) {
    notNull(transactionId, "transactionId");

    String hexId = Hex.encode(transactionId);
    Set<PendingCertificatePool.MyEntry> entries;
    synchronized  (map) {
      entries = map.remove(hexId);
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

      long now = System.currentTimeMillis();

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
