// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.CtlogControl;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.RevokeSuspendedControl;
import org.xipki.ca.api.mgmt.entry.BaseCaInfo;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.profile.ctrl.ValidityMode;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.KeySpec;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.exception.OperationException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.util.codec.Args;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.type.Validity;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CA information.
 *
 * @author Lijun Liao
 *
 */

public class CaInfo {

  private static final Logger LOG = LoggerFactory.getLogger(CaInfo.class);

  private final CaEntry caEntry;

  private final Instant noNewCertificateAfter;

  private final BigInteger serialNumber;

  private final Instant notBefore;

  private final Instant notAfter;

  private final boolean selfSigned;

  private final PublicCaInfo publicCaInfo;

  private final List<X509Cert> certchain;

  private final CertStore certStore;

  private final RandomSerialNumberGenerator randomSnGenerator;

  private final KeySpec caKeySpec;

  private Map<SignAlgo, ConcurrentContentSigner> signers;

  private ConcurrentContentSigner dfltSigner;

  private final ConfPairs extraControl;

  public CaInfo(CaEntry caEntry, CertStore certStore)
      throws OperationException {
    this.caEntry = Args.notNull(caEntry, "caEntry");
    this.certStore = certStore;

    X509Cert cert = caEntry.getCert();
    this.notBefore = cert.getNotBefore();
    this.notAfter = cert.getNotAfter();
    this.serialNumber = cert.getSerialNumber();
    this.selfSigned = cert.isSelfSigned();

    BaseCaInfo base = caEntry.getBase();
    this.publicCaInfo = new PublicCaInfo(cert, base.getCaUris(),
        base.getExtraControl());
    List<X509Cert> certs = caEntry.getCertchain();
    this.certchain = certs == null ? Collections.emptyList() : certs;
    this.noNewCertificateAfter = notAfter.minus(
        base.getExpirationPeriod(), ChronoUnit.DAYS);
    this.randomSnGenerator = RandomSerialNumberGenerator.getInstance();
    this.extraControl = base.getExtraControl();

    // keyspec
    caKeySpec = KeySpec.ofPublicKey(
        caEntry.getCert().getSubjectPublicKeyInfo());
  } // constructor

  public KeySpec getCaKeySpec() {
    return caKeySpec;
  }

  public long getNextCrlNumber() {
    return caEntry.getBase().getNextCrlNo();
  }

  public void setNextCrlNumber(long crlNumber) {
    caEntry.getBase().setNextCrlNo(crlNumber);
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

  public Instant getNoNewCertificateAfter() {
    return noNewCertificateAfter;
  }

  public CaEntry getCaEntry() {
    return caEntry;
  }

  public int getPathLenConstraint() {
    return caEntry.pathLenConstraint();
  }

  public NameId getIdent() {
    return caEntry.getIdent();
  }

  public Validity getMaxValidity() {
    return caEntry.getBase().getMaxValidity();
  }

  public X509Cert getCert() {
    return publicCaInfo.getCaCert();
  }

  public List<X509Cert> getCertchain() {
    return certchain;
  }

  public String getCrlSignerName() {
    return caEntry.getBase().getCrlSignerName();
  }

  public void setCrlSignerName(String crlSignerName) {
    caEntry.getBase().setCrlSignerName(crlSignerName);
  }

  public CrlControl getCrlControl() {
    return caEntry.getBase().getCrlControl();
  }

  public CtlogControl getCtlogControl() {
    return caEntry.getBase().getCtlogControl();
  }

  public List<String> getKeypairGenNames() {
    return caEntry.getBase().getKeypairGenNames();
  }

  public ConfPairs getExtraControl() {
    return extraControl;
  }

  public int getNumCrls() {
    return caEntry.getBase().getNumCrls();
  }

  public CaStatus getStatus() {
    return caEntry.getBase().getStatus();
  }

  public void setStatus(CaStatus status) {
    caEntry.getBase().setStatus(status);
  }

  @Override
  public String toString() {
    return caEntry.toString(false);
  }

  public String toString(boolean verbose) {
    return caEntry.toString(verbose);
  }

  public boolean isSaveCert() {
    return caEntry.getBase().isSaveCert();
  }

  public boolean isSaveKeypair() {
    return caEntry.getBase().isSaveKeypair();
  }

  public String getHexSha1OfCert() {
    return caEntry.hexSha1OfCert();
  }

  public ValidityMode getValidityMode() {
    return caEntry.getBase().getValidityMode();
  }

  public CertRevocationInfo getRevocationInfo() {
    return caEntry.getBase().getRevocationInfo();
  }

  public void setRevocationInfo(CertRevocationInfo revocationInfo) {
    caEntry.getBase().setRevocationInfo(revocationInfo);
  }

  public int getKeepExpiredCertDays() {
    return caEntry.getBase().getKeepExpiredCertDays();
  }

  public BigInteger nextSerial() {
    return randomSnGenerator.nextSerialNumber(caEntry.getBase().getSnSize());
  }

  public BigInteger nextCrlNumber() throws OperationException {
    BaseCaInfo base = caEntry.getBase();
    long crlNo = base.getNextCrlNo();
    long currentMaxNo = certStore.getMaxCrlNumber(caEntry.getIdent());
    if (crlNo <= currentMaxNo) {
      crlNo = currentMaxNo + 1;
    }
    base.setNextCrlNo(crlNo + 1);
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

  public boolean initSigner(SecurityFactory securityFactory)
      throws XiSecurityException {
    if (signers != null) {
      return true;
    }
    dfltSigner = null;

    List<CaEntry.CaSignerConf> signerConfs =
        CaEntry.splitCaSignerConfs(caEntry.getSignerConf());

    Map<SignAlgo, ConcurrentContentSigner> tmpSigners = new HashMap<>();
    for (CaEntry.CaSignerConf m : signerConfs) {
      SignerConf signerConf = new SignerConf(m.getConf());
      ConcurrentContentSigner signer;
      try {
        signer = securityFactory.createSigner(caEntry.getBase().getSignerType(),
            signerConf, caEntry.getCert());

        if (dfltSigner == null) {
          dfltSigner = signer;
        }
        tmpSigners.put(m.getAlgo(), signer);
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not initialize the CA signer for CA "
            + caEntry.getIdent().getName());
        for (ConcurrentContentSigner ccs : tmpSigners.values()) {
          ccs.close();
        }
        tmpSigners.clear();
        throw new XiSecurityException("could not initialize the CA signer");
      }
    }

    this.signers = Collections.unmodifiableMap(tmpSigners);
    return true;
  } // method initSigner

  public boolean isSignerRequired() {
    Permissions permissions = caEntry.getBase().getPermissions();
    return permissions.isPermitted(PermissionConstants.ENROLL_CROSS)
        || permissions.isPermitted(PermissionConstants.ENROLL_CERT)
        || permissions.isPermitted(PermissionConstants.GEN_CRL)
        || permissions.isPermitted(PermissionConstants.REENROLL_CERT);
  }

  public RevokeSuspendedControl revokeSuspendedCertsControl() {
    return caEntry.getBase().getRevokeSuspendedControl();
  }

}
