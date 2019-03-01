/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.cmpclient.IdentifiedObject;
import org.xipki.security.cmp.PkiStatusInfo;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class ResultEntry extends IdentifiedObject {

  public ResultEntry(String id) {
    super(id);
  }

  public static class Error extends ResultEntry {

    private final PkiStatusInfo statusInfo;

    public Error(String id, PkiStatusInfo statusInfo) {
      super(id);
      this.statusInfo = Args.notNull(statusInfo, "statusInfo");
    }

    public Error(String id, int status, int pkiFailureInfo, String statusMessage) {
      super(id);
      this.statusInfo = new PkiStatusInfo(status, pkiFailureInfo, statusMessage);
    }

    public Error(String id, int status) {
      super(id);
      this.statusInfo = new PkiStatusInfo(status);
    }

    public PkiStatusInfo getStatusInfo() {
      return statusInfo;
    }

  }

  public static class EnrollCert extends ResultEntry {

    private final CMPCertificate cert;

    private final PrivateKeyInfo privateKeyInfo;

    private final int status;

    public EnrollCert(String id, CMPCertificate cert, PrivateKeyInfo privateKeyInfo) {
      this(id, cert, privateKeyInfo, PKIStatus.GRANTED);
    }

    public EnrollCert(String id, CMPCertificate cert, PrivateKeyInfo privateKeyInfo, int status) {
      super(id);
      this.cert = cert;
      this.privateKeyInfo = privateKeyInfo;
      this.status = status;
    }

    public CMPCertificate getCert() {
      return cert;
    }

    public PrivateKeyInfo getPrivateKeyInfo() {
      return privateKeyInfo;
    }

    public int getStatus() {
      return status;
    }

  }

  public static class RevokeCert extends ResultEntry {

    private final CertId certId;

    public RevokeCert(String id, CertId certId) {
      super(id);
      this.certId = certId;
    }

    public CertId getCertId() {
      return certId;
    }

  }

  public static class UnrevokeOrRemoveCert extends ResultEntry {

    private final X500Name issuer;

    private final BigInteger serialNumber;

    private byte[] authorityKeyIdentifier;

    public UnrevokeOrRemoveCert(String id, X509Certificate cert) {
      this(id, X500Name.getInstance(cert.getIssuerX500Principal().getEncoded()),
          cert.getSerialNumber());
    }

    public UnrevokeOrRemoveCert(String id, X500Name issuer, BigInteger serialNumber) {
      super(id);
      this.serialNumber = Args.notNull(serialNumber, "serialNumber");
      this.issuer = Args.notNull(issuer, "issuer");
    }

    public X500Name getIssuer() {
      return issuer;
    }

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    public byte[] getAuthorityKeyIdentifier() {
      return authorityKeyIdentifier;
    }

    public void setAuthorityKeyIdentifier(byte[] authorityKeyIdentifier) {
      this.authorityKeyIdentifier = authorityKeyIdentifier;
    }

  }

}
