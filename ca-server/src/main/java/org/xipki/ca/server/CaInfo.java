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
import org.xipki.security.ConcurrentSigner;
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

  private Map<SignAlgo, ConcurrentSigner> signers;

  private ConcurrentSigner dfltSigner;

  private final ConfPairs extraControl;

  public CaInfo(CaEntry caEntry, CertStore certStore)
      throws OperationException {
    this.caEntry = Args.notNull(caEntry, "caEntry");
    this.certStore = certStore;

    X509Cert cert = caEntry.cert();
    this.notBefore = cert.notBefore();
    this.notAfter = cert.notAfter();
    this.serialNumber = cert.serialNumber();
    this.selfSigned = cert.isSelfSigned();

    BaseCaInfo base = caEntry.base();
    this.publicCaInfo = new PublicCaInfo(cert, base.caUris(),
        base.extraControl());
    List<X509Cert> certs = caEntry.certchain();
    this.certchain = certs == null ? Collections.emptyList() : certs;
    this.noNewCertificateAfter = notAfter.minus(
        base.expirationPeriod(), ChronoUnit.DAYS);
    this.randomSnGenerator = RandomSerialNumberGenerator.getInstance();
    this.extraControl = base.extraControl();

    // keyspec
    caKeySpec = KeySpec.ofPublicKey(
        caEntry.cert().subjectPublicKeyInfo());
  } // constructor

  public KeySpec caKeySpec() {
    return caKeySpec;
  }

  public long getNextCrlNumber() {
    return caEntry.base().nextCrlNo();
  }

  public void setNextCrlNumber(long crlNumber) {
    caEntry.base().setNextCrlNo(crlNumber);
  }

  public PublicCaInfo publicCaInfo() {
    return publicCaInfo;
  }

  public String subject() {
    return caEntry.subject();
  }

  public Instant notBefore() {
    return notBefore;
  }

  public Instant notAfter() {
    return notAfter;
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  public boolean isSelfSigned() {
    return selfSigned;
  }

  public Instant noNewCertificateAfter() {
    return noNewCertificateAfter;
  }

  public CaEntry caEntry() {
    return caEntry;
  }

  public int pathLenConstraint() {
    return caEntry.pathLenConstraint();
  }

  public NameId ident() {
    return caEntry.ident();
  }

  public Validity maxValidity() {
    return caEntry.base().maxValidity();
  }

  public X509Cert cert() {
    return publicCaInfo.caCert();
  }

  public List<X509Cert> certchain() {
    return certchain;
  }

  public String crlSignerName() {
    return caEntry.base().crlSignerName();
  }

  public void setCrlSignerName(String crlSignerName) {
    caEntry.base().setCrlSignerName(crlSignerName);
  }

  public CrlControl crlControl() {
    return caEntry.base().crlControl();
  }

  public CtlogControl ctlogControl() {
    return caEntry.base().ctlogControl();
  }

  public List<String> keypairGenNames() {
    return caEntry.base().keypairGenNames();
  }

  public ConfPairs extraControl() {
    return extraControl;
  }

  public int numCrls() {
    return caEntry.base().numCrls();
  }

  public CaStatus status() {
    return caEntry.base().status();
  }

  public void setStatus(CaStatus status) {
    caEntry.base().setStatus(status);
  }

  @Override
  public String toString() {
    return caEntry.toString(false);
  }

  public String toString(boolean verbose) {
    return caEntry.toString(verbose);
  }

  public boolean isSaveCert() {
    return caEntry.base().isSaveCert();
  }

  public boolean isSaveKeypair() {
    return caEntry.base().isSaveKeypair();
  }

  public String hexSha1OfCert() {
    return caEntry.hexSha1OfCert();
  }

  public ValidityMode validityMode() {
    return caEntry.base().validityMode();
  }

  public CertRevocationInfo revocationInfo() {
    return caEntry.base().revocationInfo();
  }

  public void setRevocationInfo(CertRevocationInfo revocationInfo) {
    caEntry.base().setRevocationInfo(revocationInfo);
  }

  public int keepExpiredCertDays() {
    return caEntry.base().keepExpiredCertDays();
  }

  public BigInteger nextSerial() {
    return randomSnGenerator.nextSerialNumber(caEntry.base().snSize());
  }

  public BigInteger nextCrlNumber() throws OperationException {
    BaseCaInfo base = caEntry.base();
    long crlNo = base.nextCrlNo();
    long currentMaxNo = certStore.getMaxCrlNumber(caEntry.ident());
    if (crlNo <= currentMaxNo) {
      crlNo = currentMaxNo + 1;
    }
    base.setNextCrlNo(crlNo + 1);
    return BigInteger.valueOf(crlNo);
  }

  public BigInteger getMaxFullCrlNumber() throws OperationException {
    long crlNumber = certStore.getMaxFullCrlNumber(caEntry.ident());
    return crlNumber == 0 ? null : BigInteger.valueOf(crlNumber);
  }

  public ConcurrentSigner getSigner(List<SignAlgo> algos) {
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
        CaEntry.splitCaSignerConfs(caEntry.signerConf());

    Map<SignAlgo, ConcurrentSigner> tmpSigners = new HashMap<>();
    for (CaEntry.CaSignerConf m : signerConfs) {
      SignerConf signerConf = new SignerConf(m.conf());
      ConcurrentSigner signer;
      try {
        signer = securityFactory.createSigner(caEntry.base().signerType(),
            signerConf, caEntry.cert());

        if (dfltSigner == null) {
          dfltSigner = signer;
        }
        tmpSigners.put(m.algo(), signer);
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not initialize the CA signer for CA "
            + caEntry.ident().name());
        for (ConcurrentSigner ccs : tmpSigners.values()) {
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
    Permissions permissions = caEntry.base().permissions();
    return permissions.isPermitted(PermissionConstants.ENROLL_CROSS)
        || permissions.isPermitted(PermissionConstants.ENROLL_CERT)
        || permissions.isPermitted(PermissionConstants.GEN_CRL)
        || permissions.isPermitted(PermissionConstants.REENROLL_CERT);
  }

  public RevokeSuspendedControl revokeSuspendedCertsControl() {
    return caEntry.base().revokeSuspendedControl();
  }

}
