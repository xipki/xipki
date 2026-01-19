// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.internal;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.List;

/**
 * Response of certificate enrollment.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class EnrollCertResponse {

  private List<CMPCertificate> caCertificates;

  private List<ResultEntry> resultEntries;

  EnrollCertResponse() {
  }

  void addCaCertificate(CMPCertificate caCertificate) {
    if (caCertificates == null) {
      caCertificates = new ArrayList<>(1);
    }
    caCertificates.add(caCertificate);
  }

  void addResultEntry(ResultEntry resultEntry) {
    Args.notNull(resultEntry, "resultEntry");

    if (!(resultEntry instanceof ResultEntry.EnrollCert
        || resultEntry instanceof ResultEntry.Error)) {
      throw new IllegalArgumentException("Unaccepted parameter of class "
          + resultEntry.getClass().getName());
    }

    if (resultEntries == null) {
      resultEntries = new ArrayList<>(1);
    }

    resultEntries.add(resultEntry);
  }

  List<CMPCertificate> getCaCertificates() {
    return caCertificates;
  }

  List<ResultEntry> getResultEntries() {
    return resultEntries;
  }

}
