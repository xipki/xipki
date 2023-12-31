// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

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
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.CtlogControl;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.RevokeSuspendedControl;
import org.xipki.ca.api.mgmt.ValidityMode;
import org.xipki.ca.api.mgmt.entry.CaConfColumn;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CaEntry.CaSignerConf;
import org.xipki.pki.ErrorCode;
import org.xipki.pki.OperationException;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.EdECConstants;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.LogUtil;
import org.xipki.util.Validity;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CA information.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CaInfo {

  private static final Logger LOG = LoggerFactory.getLogger(CaInfo.class);

  private final CaEntry caEntry;

  private final CaConfColumn caConfColumn;

  private final Instant noNewCertificateAfter;

  private final BigInteger serialNumber;

  private final Instant notBefore;

  private final Instant notAfter;

  private final boolean selfSigned;

  private final CMPCertificate certInCmpFormat;

  private final PublicCaInfo publicCaInfo;

  private final byte[] encodedSubject;

  private final List<X509Cert> certchain;

  private final List<CMPCertificate> certchainInCmpFormat;

  private final CertStore certStore;

  private final RandomSerialNumberGenerator randomSnGenerator;

  private final String caKeyspec;

  private final AlgorithmIdentifier caKeyAlgId;

  private Map<SignAlgo, ConcurrentContentSigner> signers;

  private ConcurrentContentSigner dfltSigner;

  private final ConfPairs extraControl;

  public CaInfo(CaEntry caEntry, CaConfColumn caConfColumn, CertStore certStore)
      throws OperationException {
    this.caEntry = Args.notNull(caEntry, "caEntry");
    this.caConfColumn = Args.notNull(caConfColumn, "caConfColumn");
    this.certStore = certStore;

    X509Cert cert = caEntry.getCert();
    this.notBefore = cert.getNotBefore();
    this.notAfter = cert.getNotAfter();
    this.serialNumber = cert.getSerialNumber();
    this.selfSigned = cert.isSelfSigned();
    this.certInCmpFormat = new CMPCertificate(cert.toBcCert().toASN1Structure());
    this.publicCaInfo = new PublicCaInfo(cert, caEntry.getCaUris(), caEntry.getExtraControl());
    try {
      this.encodedSubject = cert.getSubject().getEncoded();
    } catch (IOException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
    }
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
    this.noNewCertificateAfter = notAfter.minus(caEntry.getExpirationPeriod(), ChronoUnit.DAYS);
    this.randomSnGenerator = RandomSerialNumberGenerator.getInstance();
    this.extraControl = caEntry.getExtraControl();

    // keyspec
    caKeyAlgId = cert.toBcCert().getSubjectPublicKeyInfo().getAlgorithm();
    ASN1ObjectIdentifier caKeyAlgOid = caKeyAlgId.getAlgorithm();

    if (caKeyAlgOid.equals(PKCSObjectIdentifiers.rsaEncryption)) {
      java.security.interfaces.RSAPublicKey pubKey = (java.security.interfaces.RSAPublicKey) cert.getPublicKey();
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
    return caEntry.getNextCrlNo();
  }

  public void setNextCrlNumber(long crlNumber) {
    caEntry.setNextCrlNo(crlNumber);
  }

  public PublicCaInfo getPublicCaInfo() {
    return publicCaInfo;
  }

  public String getSubject() {
    return caEntry.subject();
  }

  public Instant getNotBefore() {
    return notBefore;
  }

  public Instant getNotAfter() {
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

  public Instant getNoNewCertificateAfter() {
    return noNewCertificateAfter;
  }

  public CaEntry getCaEntry() {
    return caEntry;
  }

  public CaConfColumn getCaConfColumn() {
    return caConfColumn;
  }

  public int getPathLenConstraint() {
    return caEntry.pathLenConstraint();
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

  public boolean hasSubject(byte[] subject) {
    return Arrays.equals(this.encodedSubject, subject);
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

  public CtlogControl getCtlogControl() {
    return caEntry.getCtlogControl();
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

  public boolean isSaveCert() {
    return caEntry.isSaveCert();
  }

  public boolean isSaveKeypair() {
    return caEntry.isSaveKeypair();
  }

  public String getHexSha1OfCert() {
    return caEntry.hexSha1OfCert();
  }

  public ValidityMode getValidityMode() {
    return caEntry.getValidityMode();
  }

  public Permissions getPermission() {
    return caEntry.getPermissions();
  }

  public void setPermissions(Permissions permission) {
    caEntry.setPermissions(permission);
  }

  public CertRevocationInfo getRevocationInfo() {
    return caEntry.getRevocationInfo();
  }

  public void setRevocationInfo(CertRevocationInfo revocationInfo) {
    caEntry.setRevocationInfo(revocationInfo);
  }

  public int getKeepExpiredCertDays() {
    return caEntry.getKeepExpiredCertDays();
  }

  public BigInteger nextSerial() {
    return randomSnGenerator.nextSerialNumber(caEntry.getSnSize());
  }

  public BigInteger nextCrlNumber() throws OperationException {
    long crlNo = caEntry.getNextCrlNo();
    long currentMaxNo = certStore.getMaxCrlNumber(caEntry.getIdent());
    if (crlNo <= currentMaxNo) {
      crlNo = currentMaxNo + 1;
    }
    caEntry.setNextCrlNo(crlNo + 1);
    return BigInteger.valueOf(crlNo);
  }

  public BigInteger getMaxFullCrlNumber() throws OperationException {
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

  public boolean initSigner(SecurityFactory securityFactory) throws XiSecurityException {
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
        signer = securityFactory.createSigner(caEntry.getSignerType(), signerConf, caEntry.getCert());
        if (dfltSigner == null) {
          dfltSigner = signer;
        }
        tmpSigners.put(m.getAlgo(), signer);
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not initialize the CA signer for CA " + caEntry.getIdent().getName());
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
    Permissions permissions = caEntry.getPermissions();
    return permissions.isPermitted(PermissionConstants.ENROLL_CROSS)
        || permissions.isPermitted(PermissionConstants.ENROLL_CERT)
        || permissions.isPermitted(PermissionConstants.GEN_CRL)
        || permissions.isPermitted(PermissionConstants.REENROLL_CERT);
  }

  public RevokeSuspendedControl revokeSuspendedCertsControl() {
    return caEntry.getRevokeSuspendedControl();
  }

}
