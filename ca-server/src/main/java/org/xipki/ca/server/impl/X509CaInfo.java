/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.server.impl;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.impl.store.CertificateStore;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.ca.server.mgmt.api.PermissionConstants;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.api.x509.RevokeSuspendedCertsControl;
import org.xipki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.exception.XiSecurityException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CaInfo {

  private static final long MS_PER_DAY = 24L * 60 * 60 * 1000;

  private final X509CaEntry caEntry;

  private long noNewCertificateAfter;

  private BigInteger serialNumber;

  private Date notBefore;

  private Date notAfter;

  private boolean selfSigned;

  private CMPCertificate certInCmpFormat;

  private PublicCaInfo publicCaInfo;

  private CertificateStore certStore;

  private RandomSerialNumberGenerator randomSnGenerator;

  private Map<String, ConcurrentContentSigner> signers;

  private ConcurrentContentSigner dfltSigner;

  private RevokeSuspendedCertsControl revokeSuspendedCertsControl;

  public X509CaInfo(X509CaEntry caEntry, CertificateStore certStore) throws OperationException {
    this.caEntry = ParamUtil.requireNonNull("caEntry", caEntry);
    this.certStore = ParamUtil.requireNonNull("certStore", certStore);

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
      throw new OperationException(ErrorCode.SYSTEM_FAILURE,
          "could not encode the CA certificate");
    }
    this.certInCmpFormat = new CMPCertificate(bcCert);

    this.publicCaInfo = new PublicCaInfo(cert, caEntry.getCacertUris(), caEntry.getOcspUris(),
        caEntry.getCrlUris(), caEntry.getDeltaCrlUris(), caEntry.getExtraControl());

    this.noNewCertificateAfter =
        this.notAfter.getTime() - MS_PER_DAY * caEntry.getExpirationPeriod();

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

  public X509CaEntry getCaEntry() {
    return caEntry;
  }

  public NameId getIdent() {
    return caEntry.getIdent();
  }

  public List<String> getCrlUris() {
    return caEntry.getCrlUris();
  }

  public String getCrlUrisAsString() {
    return caEntry.getCrlUrisAsString();
  }

  public List<String> getDeltaCrlUris() {
    return caEntry.getDeltaCrlUris();
  }

  public String getDeltaCrlUrisAsString() {
    return caEntry.getDeltaCrlUrisAsString();
  }

  public List<String> getOcspUris() {
    return caEntry.getOcspUris();
  }

  public String getOcspUrisAsString() {
    return caEntry.getOcspUrisAsString();
  }

  public CertValidity getMaxValidity() {
    return caEntry.getMaxValidity();
  }

  public void setMaxValidity(CertValidity maxValidity) {
    caEntry.setMaxValidity(maxValidity);
  }

  public X509Cert getCert() {
    return publicCaInfo.getCaCert();
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

  public String getCmpControlName() {
    return caEntry.getCmpControlName();
  }

  public void setCmpControlName(String name) {
    caEntry.setCmpControlName(name);
  }

  public String getResponderName() {
    return caEntry.getResponderName();
  }

  public void setResponderName(String name) {
    caEntry.setResponderName(name);
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

  public Date getCrlBaseTime() {
    return caEntry.getCrlBaseTime();
  }

  public BigInteger nextSerial() throws OperationException {
    return randomSnGenerator.nextSerialNumber(caEntry.getserialNoBitLen());
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

    List<String[]> signerConfs = CaEntry.splitCaSignerConfs(caEntry.getSignerConf());

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
          ccs.shutdown();
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

  public RevokeSuspendedCertsControl revokeSuspendedCertsControl() {
    return revokeSuspendedCertsControl;
  }

  public void setRevokeSuspendedCertsControl(
      RevokeSuspendedCertsControl revokeSuspendedCertsControl) {
    this.revokeSuspendedCertsControl = revokeSuspendedCertsControl;
  }

}
