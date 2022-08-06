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
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.cmpclient.IdentifiedObject;
import org.xipki.security.cmp.PkiStatusInfo;

import java.math.BigInteger;

import static org.xipki.util.Args.notNull;

/**
 * Result entry.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class ResultEntry extends IdentifiedObject {

  ResultEntry(String id) {
    super(id);
  }

  static class Error extends ResultEntry {

    private final PkiStatusInfo statusInfo;

    Error(String id, int status, int pkiFailureInfo, String statusMessage) {
      super(id);
      this.statusInfo = new PkiStatusInfo(status, pkiFailureInfo, statusMessage);
    }

    Error(String id, int status) {
      super(id);
      this.statusInfo = new PkiStatusInfo(status);
    }

    PkiStatusInfo getStatusInfo() {
      return statusInfo;
    }

  } // class Error

  static class EnrollCert extends ResultEntry {

    private final CMPCertificate cert;

    private final PrivateKeyInfo privateKeyInfo;

    private final int status;

    EnrollCert(String id, CMPCertificate cert, PrivateKeyInfo privateKeyInfo, int status) {
      super(id);
      this.cert = cert;
      this.privateKeyInfo = privateKeyInfo;
      this.status = status;
    }

    CMPCertificate getCert() {
      return cert;
    }

    PrivateKeyInfo getPrivateKeyInfo() {
      return privateKeyInfo;
    }

    int getStatus() {
      return status;
    }

  } // class EnrollCert

  static class RevokeCert extends ResultEntry {

    private final CertId certId;

    RevokeCert(String id, CertId certId) {
      super(id);
      this.certId = certId;
    }

    CertId getCertId() {
      return certId;
    }

  } // class RevokeCert

  static class UnrevokeOrRemoveCert extends ResultEntry {

    private final X500Name issuer;

    private final BigInteger serialNumber;

    private byte[] authorityKeyIdentifier;

    UnrevokeOrRemoveCert(String id, X500Name issuer, BigInteger serialNumber) {
      super(id);
      this.serialNumber = notNull(serialNumber, "serialNumber");
      this.issuer = notNull(issuer, "issuer");
    }

    X500Name getIssuer() {
      return issuer;
    }

    BigInteger getSerialNumber() {
      return serialNumber;
    }

    byte[] getAuthorityKeyIdentifier() {
      return authorityKeyIdentifier;
    }

    void setAuthorityKeyIdentifier(byte[] authorityKeyIdentifier) {
      this.authorityKeyIdentifier = authorityKeyIdentifier;
    }

  } // class UnrevokeOrRemoveCert

}
