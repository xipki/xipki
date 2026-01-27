// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.internal;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.cmp.client.IdentifiedObject;
import org.xipki.security.cmp.PkiStatusInfo;
import org.xipki.util.codec.Args;

import java.math.BigInteger;

/**
 * Result entry.
 *
 * @author Lijun Liao (xipki)
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
      this.statusInfo = new PkiStatusInfo(status, pkiFailureInfo,
          statusMessage);
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

    EnrollCert(String id, CMPCertificate cert, PrivateKeyInfo privateKeyInfo,
               int status) {
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
      this.serialNumber = Args.notNull(serialNumber, "serialNumber");
      this.issuer = Args.notNull(issuer, "issuer");
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
