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

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.mgmt.*;
import org.xipki.ca.api.mgmt.entry.CaConfColumn;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CaEntry.CaSignerConf;
import org.xipki.ca.server.db.CertStore;
import org.xipki.security.*;
import org.xipki.util.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

/**
 * CA information.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaInfo {

  private static final Logger LOG = LoggerFactory.getLogger(CaInfo.class);

  private static final long MS_PER_DAY = 24L * 60 * 60 * 1000;

  private final CaEntry caEntry;

  private final CaConfColumn caConfColumn;

  private final long noNewCertificateAfter;

  private final BigInteger serialNumber;

  private final Date notBefore;

  private final Date notAfter;

  private final boolean selfSigned;

  private final CMPCertificate certInCmpFormat;

  private final PublicCaInfo publicCaInfo;

  private final List<X509Cert> certchain;

  private final List<CMPCertificate> certchainInCmpFormat;

  private final CertStore certStore;

  private final RandomSerialNumberGenerator randomSnGenerator;

  private final String caKeyspec;

  private final AlgorithmIdentifier caKeyAlgId;

  private Map<SignAlgo, ConcurrentContentSigner> signers;

  private ConcurrentContentSigner dfltSigner;

  private ConfPairs extraControl;

  public CaInfo(CaEntry caEntry, CaConfColumn caConfColumn, CertStore certStore)
      throws OperationException {
    this.caEntry = Args.notNull(caEntry, "caEntry");
    this.caConfColumn = Args.notNull(caConfColumn, "caConfColumn");
    this.certStore = Args.notNull(certStore, "certStore");

    X509Cert cert = caEntry.getCert();
    this.notBefore = cert.getNotBefore();
    this.notAfter = cert.getNotAfter();
    this.serialNumber = cert.getSerialNumber();
    this.selfSigned = cert.isSelfSigned();
    this.certInCmpFormat = new CMPCertificate(cert.toBcCert().toASN1Structure());
    this.publicCaInfo = new PublicCaInfo(cert, caEntry.getCaUris(), caEntry.getExtraControl());
    List<X509Cert> certs = caEntry.getCertchain();
    if (certs == null || certs.isEmpty()) {
      this.certchain = Collections.emptyList();
      this.certchainInCmpFormat = Collections.emptyList();
    } else {
      this.certchain = new ArrayList<>(certs);
      this.certchainInCmpFormat = new ArrayList<>(certs.size());
      for (X509Cert c : certs) {
        this.certchainInCmpFormat.add(new CMPCertificate(c.toBcCert().toASN1Structure()));
      }
    }
    this.noNewCertificateAfter = notAfter.getTime() - MS_PER_DAY * caEntry.getExpirationPeriod();
    this.randomSnGenerator = RandomSerialNumberGenerator.getInstance();
    this.extraControl = caEntry.getExtraControl();

    // keyspec
    caKeyAlgId = cert.toBcCert().getSubjectPublicKeyInfo().getAlgorithm();
    ASN1ObjectIdentifier caKeyAlgOid = caKeyAlgId.getAlgorithm();

    if (caKeyAlgOid.equals(PKCSObjectIdentifiers.rsaEncryption)) {
      java.security.interfaces.RSAPublicKey pubKey =
          (java.security.interfaces.RSAPublicKey) cert.getPublicKey();
      caKeyspec = "RSA/" + pubKey.getModulus().bitLength();
    } else if (caKeyAlgOid.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
      ASN1ObjectIdentifier curveOid = ASN1ObjectIdentifier.getInstance(caKeyAlgId.getParameters());
      caKeyspec = "EC/" + curveOid.getId();
    } else if (caKeyAlgOid.equals(X9ObjectIdentifiers.id_dsa)) {
      ASN1Sequence seq = DERSequence.getInstance(caKeyAlgId.getParameters());
      BigInteger p = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
      BigInteger q = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
      caKeyspec = "DSA/" + p.bitLength() + "/" + q.bitLength();
    } else if (caKeyAlgOid.equals(EdECConstants.id_ED25519)) {
      caKeyspec = "ED25519";
    } else if (caKeyAlgOid.equals(EdECConstants.id_ED448)) {
      caKeyspec ="ED448";
    } else {
      throw new IllegalStateException("unknown key algorithm " + caKeyAlgOid.getId());
    }
  } // constructor

  public String getCaKeyspec() {
    return caKeyspec;
  }

  public AlgorithmIdentifier getCaKeyAlgId() {
    return caKeyAlgId;
  }

  public long getNextCrlNumber() {
    return caEntry.getNextCrlNumber();
  }

  public void setNextCrlNumber(long crlNumber) {
    caEntry.setNextCrlNumber(crlNumber);
  }

  public PublicCaInfo getPublicCaInfo() {
    return publicCaInfo;
  }

  public String getSubject() {
    return caEntry.getSubject();
  }

  public Date getNotBefore() {
    return notBefore;
  }

  public Date getNotAfter() {
    return notAfter;
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public boolean isSelfSigned() {
    return selfSigned;
  }

  public CMPCertificate getCertInCmpFormat() {
    return certInCmpFormat;
  }

  public long getNoNewCertificateAfter() {
    return noNewCertificateAfter;
  }

  public CaEntry getCaEntry() {
    return caEntry;
  }

  public CaConfColumn getCaConfColumn() {
    return caConfColumn;
  }

  public int getPathLenConstraint() {
    return caEntry.getPathLenConstraint();
  }

  public NameId getIdent() {
    return caEntry.getIdent();
  }

  public CaUris getCaUris() {
    return caEntry.getCaUris();
  }

  public Validity getMaxValidity() {
    return caEntry.getMaxValidity();
  }

  public X509Cert getCert() {
    return publicCaInfo.getCaCert();
  }

  public List<X509Cert> getCertchain() {
    return certchain;
  }

  public List<CMPCertificate> getCertchainInCmpFormat() {
    return certchainInCmpFormat;
  }

  public String getCrlSignerName() {
    return caEntry.getCrlSignerName();
  }

  public void setCrlSignerName(String crlSignerName) {
    caEntry.setCrlSignerName(crlSignerName);
  }

  public CrlControl getCrlControl() {
    return caEntry.getCrlControl();
  }

  public String getCmpResponderName() {
    return caEntry.getCmpResponderName();
  }

  public void setCmpResponderName(String name) {
    caEntry.setCmpResponderName(name);
  }

  public CmpControl getCmpControl() {
    return caEntry.getCmpControl();
  }

  public CtlogControl getCtlogControl() {
    return caEntry.getCtlogControl();
  }

  public PopoControl getPopoControl() {
    return caEntry.getPopoControl();
  }

  public String getScepResponderName() {
    return caEntry.getScepResponderName();
  }

  public void setScepResponderName(String name) {
    caEntry.setScepResponderName(name);
  }

  public List<String> getKeypairGenNames() {
    return caEntry.getKeypairGenNames();
  }

  public ConfPairs getExtraControl() {
    return extraControl;
  }

  public int getNumCrls() {
    return caEntry.getNumCrls();
  }

  public CaStatus getStatus() {
    return caEntry.getStatus();
  }

  public void setStatus(CaStatus status) {
    caEntry.setStatus(status);
  }

  @Override
  public String toString() {
    return caEntry.toString(false);
  }

  public String toString(boolean verbose) {
    return caEntry.toString(verbose);
  }

  public boolean supportsCmp() {
    return caEntry.getProtocoSupport().isCmp();
  }

  public boolean supportsRest() {
    return caEntry.getProtocoSupport().isRest();
  }

  public boolean supportsScep() {
    return caEntry.getProtocoSupport().isScep();
  }

  public boolean isSaveCert() {
    return caEntry.isSaveCert();
  }

  public boolean isSaveRequest() {
    return caEntry.isSaveRequest();
  }

  public void setSaveRequest(boolean saveRequest) {
    caEntry.setSaveRequest(saveRequest);
  }

  public boolean isSaveKeypair() {
    return caEntry.isSaveKeypair();
  }

  public String getHexSha1OfCert() {
    return caEntry.getHexSha1OfCert();
  }

  public ValidityMode getValidityMode() {
    return caEntry.getValidityMode();
  }

  public int getPermission() {
    return caEntry.getPermission();
  }

  public void setPermission(int permission) {
    caEntry.setPermission(permission);
  }

  public CertRevocationInfo getRevocationInfo() {
    return caEntry.getRevocationInfo();
  }

  public void setRevocationInfo(CertRevocationInfo revocationInfo) {
    caEntry.setRevocationInfo(revocationInfo);
  }

  public int getKeepExpiredCertInDays() {
    return caEntry.getKeepExpiredCertInDays();
  }

  public BigInteger nextSerial() {
    return randomSnGenerator.nextSerialNumber(caEntry.getSerialNoLen());
  }

  public BigInteger nextCrlNumber()
      throws OperationException {
    long crlNo = caEntry.getNextCrlNumber();
    long currentMaxNo = certStore.getMaxCrlNumber(caEntry.getIdent());
    if (crlNo <= currentMaxNo) {
      crlNo = currentMaxNo + 1;
    }
    caEntry.setNextCrlNumber(crlNo + 1);
    return BigInteger.valueOf(crlNo);
  }

  public BigInteger getMaxFullCrlNumber()
      throws OperationException {
    long crlNumber = certStore.getMaxFullCrlNumber(caEntry.getIdent());
    return crlNumber == 0 ? null : BigInteger.valueOf(crlNumber);
  }

  public ConcurrentContentSigner getSigner(List<SignAlgo> algos) {
    if (CollectionUtil.isEmpty(algos)) {
      return dfltSigner;
    }

    for (SignAlgo m : algos) {
      if (signers.containsKey(m)) {
        return signers.get(m);
      }
    }

    return null;
  } // method getSigner

  public boolean initSigner(SecurityFactory securityFactory)
      throws XiSecurityException {
    if (signers != null) {
      return true;
    }
    dfltSigner = null;

    List<CaSignerConf> signerConfs = CaEntry.splitCaSignerConfs(caEntry.getSignerConf());

    Map<SignAlgo, ConcurrentContentSigner> tmpSigners = new HashMap<>();
    for (CaSignerConf m : signerConfs) {
      SignerConf signerConf = new SignerConf(m.getConf());
      ConcurrentContentSigner signer;
      try {
        signer = securityFactory.createSigner(caEntry.getSignerType(), signerConf,
            caEntry.getCert());
        if (dfltSigner == null) {
          dfltSigner = signer;
        }
        tmpSigners.put(m.getAlgo(), signer);
      } catch (Throwable th) {
        LogUtil.error(LOG, th,
                "could not initialize the CA signer for CA " + caEntry.getIdent().getName());
        for (ConcurrentContentSigner ccs : tmpSigners.values()) {
          try {
            ccs.close();
          } catch (IOException ex) {
            LogUtil.error(LOG, ex, "could not close ConcurrentContentSigner " + ccs.getName());
          }
        }
        tmpSigners.clear();
        throw new XiSecurityException("could not initialize the CA signer");
      }
    }

    this.signers = Collections.unmodifiableMap(tmpSigners);
    return true;
  } // method initSigner

  public boolean isSignerRequired() {
    int permission = caEntry.getPermission();
    return PermissionConstants.contains(permission, PermissionConstants.ENROLL_CROSS)
        || PermissionConstants.contains(permission, PermissionConstants.ENROLL_CERT)
        || PermissionConstants.contains(permission, PermissionConstants.GEN_CRL)
        || PermissionConstants.contains(permission, PermissionConstants.KEY_UPDATE);
  } // method isSignerRequired

  public RevokeSuspendedControl revokeSuspendedCertsControl() {
    return caEntry.getRevokeSuspendedControl();
  }

}
