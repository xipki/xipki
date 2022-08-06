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

package org.xipki.cmpclient.internal;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.xipki.util.Args;

import java.util.ArrayList;
import java.util.List;

/**
 * Response of certificate enrollment.
 *
 * @author Lijun Liao
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
      throw new IllegalArgumentException(
          "Unaccepted parameter of class " + resultEntry.getClass().getName());
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
