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

package org.xipki.ca.server;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CmpControl;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.CtLogControl;
import org.xipki.ca.api.mgmt.MgmtEntry;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.ProtocolSupport;
import org.xipki.ca.api.mgmt.RevokeSuspendedCertsControl;
import org.xipki.ca.api.mgmt.ScepControl;
import org.xipki.ca.api.mgmt.ValidityMode;
import org.xipki.ca.server.store.CertStore;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.Validity;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaInfo {

  private static final Logger LOG = LoggerFactory.getLogger(CaInfo.class);

  private static final long MS_PER_DAY = 24L * 60 * 60 * 1000;

  private final MgmtEntry.Ca caEntry;

  private final long noNewCertificateAfter;

  private final BigInteger serialNumber;

  private final Date notBefore;

  private final Date notAfter;

  private final boolean selfSigned;

  private final CMPCertificate certInCmpFormat;

  private final PublicCaInfo publicCaInfo;

  private final List<X509Cert> certchain;

  private final CertStore certStore;

  private final RandomSerialNumberGenerator randomSnGenerator;

  private DhpocControl dhpocControl;

  private Map<String, ConcurrentContentSigner> signers;

  private ConcurrentContentSigner dfltSigner;

  private RevokeSuspendedCertsControl revokeSuspendedCertsControl;

  public CaInfo(MgmtEntry.Ca caEntry, CertStore certStore) throws OperationException {
    this.caEntry = Args.notNull(caEntry, "caEntry");
    this.certStore = Args.notNull(certStore, "certStore");

    X509Certificate cert = caEntry.getCert();
    this.notBefore = cert.getNotBefore();
    this.notAfter = cert.getNotAfter();
    this.serialNumber = cert.getSerialNumber();
    this.selfSigned = cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());

    Certificate bcCert;
    try {
      byte[] encodedCert = cert.getEncoded();
      bcCert = Certificate.getInstance(encodedCert);
    } catch (CertificateEncodingException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, "could not encode the CA certificate");
    }
    this.certInCmpFormat = new CMPCertificate(bcCert);

    this.publicCaInfo = new PublicCaInfo(cert, caEntry.getCaUris(), caEntry.getExtraControl());
    List<X509Certificate> certs = caEntry.getCertchain();
    this.certchain = new LinkedList<>();
    if (CollectionUtil.isNonEmpty(certs)) {
      for (X509Certificate m : certs) {
        this.certchain.add(new X509Cert(m));
      }
    }

    this.noNewCertificateAfter = notAfter.getTime() - MS_PER_DAY * caEntry.getExpirationPeriod();

    this.randomSnGenerator = RandomSerialNumberGenerator.getInstance();
  } // constructor

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

  public MgmtEntry.Ca getCaEntry() {
    return caEntry;
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

  public void setMaxValidity(Validity maxValidity) {
    caEntry.setMaxValidity(maxValidity);
  }

  public X509Cert getCert() {
    return publicCaInfo.getCaCert();
  }

  public List<X509Cert> getCertchain() {
    return certchain;
  }

  public String getSignerConf() {
    return caEntry.getSignerConf();
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

  public void setCrlControl(CrlControl crlControl) {
    caEntry.setCrlControl(crlControl);
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

  public void setCmpControl(CmpControl cmpControl) {
    caEntry.setCmpControl(cmpControl);
  }

  public CtLogControl getCtLogControl() {
    return caEntry.getCtLogControl();
  }

  public DhpocControl getDhpocControl() {
    return dhpocControl;
  }

  public String getScepResponderName() {
    return caEntry.getScepResponderName();
  }

  public void setScepResponderName(String name) {
    caEntry.setScepResponderName(name);
  }

  public ScepControl getSCepControl() {
    return caEntry.getScepControl();
  }

  public void setScepControl(ScepControl control) {
    caEntry.setScepControl(control);
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

  public String getSignerType() {
    return caEntry.getSignerType();
  }

  @Override
  public String toString() {
    return caEntry.toString(false);
  }

  public String toString(boolean verbose) {
    return caEntry.toString(verbose);
  }

  public boolean isDuplicateKeyPermitted() {
    return caEntry.isDuplicateKeyPermitted();
  }

  public void setDuplicateKeyPermitted(boolean permitted) {
    caEntry.setDuplicateKeyPermitted(permitted);
  }

  public boolean isDuplicateSubjectPermitted() {
    return caEntry.isDuplicateSubjectPermitted();
  }

  public void setDuplicateSubjectPermitted(boolean permitted) {
    caEntry.setDuplicateSubjectPermitted(permitted);
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

  public void setProtocolSupport(ProtocolSupport protocolSupport) {
    caEntry.setProtocolSupport(protocolSupport);
  }

  public boolean isSaveRequest() {
    return caEntry.isSaveRequest();
  }

  public void setSaveRequest(boolean saveRequest) {
    caEntry.setSaveRequest(saveRequest);
  }

  public ValidityMode getValidityMode() {
    return caEntry.getValidityMode();
  }

  public void setValidityMode(ValidityMode mode) {
    caEntry.setValidityMode(mode);
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

  public int getExpirationPeriod() {
    return caEntry.getExpirationPeriod();
  }

  public void setKeepExpiredCertInDays(int days) {
    caEntry.setKeepExpiredCertInDays(days);
  }

  public int getKeepExpiredCertInDays() {
    return caEntry.getKeepExpiredCertInDays();
  }

  public BigInteger nextSerial() throws OperationException {
    return randomSnGenerator.nextSerialNumber(caEntry.getSerialNoBitLen());
  }

  public BigInteger nextCrlNumber() throws OperationException {
    long crlNo = caEntry.getNextCrlNumber();
    long currentMaxNo = certStore.getMaxCrlNumber(caEntry.getIdent());
    if (crlNo <= currentMaxNo) {
      crlNo = currentMaxNo + 1;
    }
    caEntry.setNextCrlNumber(crlNo + 1);
    return BigInteger.valueOf(crlNo);
  }

  public ConcurrentContentSigner getSigner(List<String> algoNames) {
    if (CollectionUtil.isEmpty(algoNames)) {
      return dfltSigner;
    }

    for (String name : algoNames) {
      if (signers.containsKey(name)) {
        return signers.get(name);
      }
    }

    return null;
  }

  public boolean initSigner(SecurityFactory securityFactory) throws XiSecurityException {
    if (signers != null) {
      return true;
    }
    dfltSigner = null;

    List<String[]> signerConfs = MgmtEntry.Ca.splitCaSignerConfs(caEntry.getSignerConf());

    Map<String, ConcurrentContentSigner> tmpSigners = new HashMap<>();
    for (String[] m : signerConfs) {
      String algo = m[0];
      SignerConf signerConf = new SignerConf(m[1]);
      ConcurrentContentSigner signer;
      try {
        signer = securityFactory.createSigner(caEntry.getSignerType(), signerConf,
            caEntry.getCert());
        if (dfltSigner == null) {
          dfltSigner = signer;
        }
        tmpSigners.put(algo, signer);
      } catch (Throwable th) {
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

  public boolean initDhpocControl(SecurityFactory securityFactory) throws XiSecurityException {
    if (dhpocControl != null) {
      return true;
    }

    if (caEntry.getDhpocControl() != null) {
      this.dhpocControl = new DhpocControl(caEntry.getDhpocControl(), securityFactory);
    } else {
      this.dhpocControl = null;
    }
    return true;
  }

  public boolean isSignerRequired() {
    int permission = caEntry.getPermission();
    return PermissionConstants.contains(permission, PermissionConstants.ENROLL_CROSS)
        || PermissionConstants.contains(permission, PermissionConstants.ENROLL_CERT)
        || PermissionConstants.contains(permission, PermissionConstants.GEN_CRL)
        || PermissionConstants.contains(permission, PermissionConstants.KEY_UPDATE);
  } // method isSignerRequired

  public RevokeSuspendedCertsControl revokeSuspendedCertsControl() {
    return revokeSuspendedCertsControl;
  }

  public void setRevokeSuspendedCertsControl(
      RevokeSuspendedCertsControl revokeSuspendedCertsControl) {
    this.revokeSuspendedCertsControl = revokeSuspendedCertsControl;
  }

}
