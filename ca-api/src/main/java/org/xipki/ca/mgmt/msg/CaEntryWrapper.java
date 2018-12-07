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

package org.xipki.ca.mgmt.msg;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.ca.mgmt.api.CaStatus;
import org.xipki.ca.mgmt.api.CmpControl;
import org.xipki.ca.mgmt.api.CrlControl;
import org.xipki.ca.mgmt.api.MgmtEntry;
import org.xipki.ca.mgmt.api.ProtocolSupport;
import org.xipki.ca.mgmt.api.ScepControl;
import org.xipki.ca.mgmt.api.ValidityMode;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.util.X509Util;
import org.xipki.util.ConfPairs;
import org.xipki.util.InvalidConfException;

/**
 * TODO.
 * @author Lijun Liao
 */

public class CaEntryWrapper {

  private NameId ident;

  private CaStatus status;

  private Certprofile.CertValidity maxValidity;

  private String signerType;

  private String signerConf;

  private String scepControl;

  private String crlControl;

  private String crlSignerName;

  private String cmpControl;

  private String cmpResponderName;

  private String scepResponderName;

  private boolean duplicateKeyPermitted;

  private boolean duplicateSubjectPermitted;

  private ProtocolSupport protocolSupport;

  private boolean saveRequest;

  private ValidityMode validityMode = ValidityMode.STRICT;

  private int permission;

  private int expirationPeriod;

  private int keepExpiredCertInDays;

  private String extraControl;

  private CaUris caUris;

  private byte[] certBytes;

  private int serialNoBitLen;

  private long nextCrlNumber;

  private int numCrls;

  private CertRevocationInfo revocationInfo;

  public CaEntryWrapper() {
  }

  public CaEntryWrapper(MgmtEntry.Ca caEntry) {
    ident = caEntry.getIdent();
    status = caEntry.getStatus();
    maxValidity = caEntry.getMaxValidity();
    signerType = caEntry.getSignerType();
    signerConf = caEntry.getSignerConf();
    if (caEntry.getScepControl() != null) {
      scepControl = caEntry.getScepControl().getConf();
    }

    if (caEntry.getCrlControl() != null) {
      crlControl = caEntry.getCrlControl().getConf();
    }

    crlSignerName = caEntry.getCrlSignerName();

    if (caEntry.getCmpControl() != null) {
      cmpControl = caEntry.getCmpControl().getConf();
    }

    cmpResponderName = caEntry.getCmpResponderName();
    scepResponderName = caEntry.getScepResponderName();
    duplicateKeyPermitted = caEntry.isDuplicateKeyPermitted();
    duplicateSubjectPermitted = caEntry.isDuplicateSubjectPermitted();
    protocolSupport = caEntry.getProtocoSupport();
    saveRequest = caEntry.isSaveRequest();
    validityMode = caEntry.getValidityMode();
    permission = caEntry.getPermission();
    expirationPeriod = caEntry.getExpirationPeriod();
    keepExpiredCertInDays = caEntry.getKeepExpiredCertInDays();

    if (caEntry.getExtraControl() != null) {
      extraControl = caEntry.getExtraControl().getEncoded();
    }

    caUris = caEntry.getCaUris();

    if (caEntry.getCert() != null) {
      try {
        certBytes = caEntry.getCert().getEncoded();
      } catch (CertificateEncodingException ex) {
        throw new IllegalStateException("could not encode certificate", ex);
      }
    }

    serialNoBitLen = caEntry.getSerialNoBitLen();

    nextCrlNumber = caEntry.getNextCrlNumber();

    numCrls = caEntry.getNumCrls();

    revocationInfo = caEntry.getRevocationInfo();

  }

  public NameId getIdent() {
    return ident;
  }

  public void setIdent(NameId ident) {
    this.ident = ident;
  }

  public CaStatus getStatus() {
    return status;
  }

  public void setStatus(CaStatus status) {
    this.status = status;
  }

  public Certprofile.CertValidity getMaxValidity() {
    return maxValidity;
  }

  public void setMaxValidity(Certprofile.CertValidity maxValidity) {
    this.maxValidity = maxValidity;
  }

  public String getSignerType() {
    return signerType;
  }

  public void setSignerType(String signerType) {
    this.signerType = signerType;
  }

  public String getSignerConf() {
    return signerConf;
  }

  public void setSignerConf(String signerConf) {
    this.signerConf = signerConf;
  }

  public String getScepControl() {
    return scepControl;
  }

  public void setScepControl(String scepControl) {
    this.scepControl = scepControl;
  }

  public String getCrlControl() {
    return crlControl;
  }

  public void setCrlControl(String crlControl) {
    this.crlControl = crlControl;
  }

  public String getCrlSignerName() {
    return crlSignerName;
  }

  public void setCrlSignerName(String crlSignerName) {
    this.crlSignerName = crlSignerName;
  }

  public String getCmpControl() {
    return cmpControl;
  }

  public void setCmpControl(String cmpControl) {
    this.cmpControl = cmpControl;
  }

  public String getCmpResponderName() {
    return cmpResponderName;
  }

  public void setCmpResponderName(String cmpResponderName) {
    this.cmpResponderName = cmpResponderName;
  }

  public String getScepResponderName() {
    return scepResponderName;
  }

  public void setScepResponderName(String scepResponderName) {
    this.scepResponderName = scepResponderName;
  }

  public boolean isDuplicateKeyPermitted() {
    return duplicateKeyPermitted;
  }

  public void setDuplicateKeyPermitted(boolean duplicateKeyPermitted) {
    this.duplicateKeyPermitted = duplicateKeyPermitted;
  }

  public boolean isDuplicateSubjectPermitted() {
    return duplicateSubjectPermitted;
  }

  public void setDuplicateSubjectPermitted(boolean duplicateSubjectPermitted) {
    this.duplicateSubjectPermitted = duplicateSubjectPermitted;
  }

  public ProtocolSupport getProtocolSupport() {
    return protocolSupport;
  }

  public void setProtocolSupport(ProtocolSupport protocolSupport) {
    this.protocolSupport = protocolSupport;
  }

  public boolean isSaveRequest() {
    return saveRequest;
  }

  public void setSaveRequest(boolean saveRequest) {
    this.saveRequest = saveRequest;
  }

  public ValidityMode getValidityMode() {
    return validityMode;
  }

  public void setValidityMode(ValidityMode validityMode) {
    this.validityMode = validityMode;
  }

  public int getPermission() {
    return permission;
  }

  public void setPermission(int permission) {
    this.permission = permission;
  }

  public int getExpirationPeriod() {
    return expirationPeriod;
  }

  public void setExpirationPeriod(int expirationPeriod) {
    this.expirationPeriod = expirationPeriod;
  }

  public int getKeepExpiredCertInDays() {
    return keepExpiredCertInDays;
  }

  public void setKeepExpiredCertInDays(int keepExpiredCertInDays) {
    this.keepExpiredCertInDays = keepExpiredCertInDays;
  }

  public String getExtraControl() {
    return extraControl;
  }

  public void setExtraControl(String extraControl) {
    this.extraControl = extraControl;
  }

  public CaUris getCaUris() {
    return caUris;
  }

  public void setCaUris(CaUris caUris) {
    this.caUris = caUris;
  }

  public byte[] getCertBytes() {
    return certBytes;
  }

  public void setCertBytes(byte[] certBytes) {
    this.certBytes = certBytes;
  }

  public int getSerialNoBitLen() {
    return serialNoBitLen;
  }

  public void setSerialNoBitLen(int serialNoBitLen) {
    this.serialNoBitLen = serialNoBitLen;
  }

  public long getNextCrlNumber() {
    return nextCrlNumber;
  }

  public void setNextCrlNumber(long nextCrlNumber) {
    this.nextCrlNumber = nextCrlNumber;
  }

  public int getNumCrls() {
    return numCrls;
  }

  public void setNumCrls(int numCrls) {
    this.numCrls = numCrls;
  }

  public CertRevocationInfo getRevocationInfo() {
    return revocationInfo;
  }

  public void setRevocationInfo(CertRevocationInfo revocationInfo) {
    this.revocationInfo = revocationInfo;
  }

  public MgmtEntry.Ca toCaEntry()
      throws CertificateException, CaMgmtException, InvalidConfException {
    MgmtEntry.Ca rv = new MgmtEntry.Ca(ident, serialNoBitLen, nextCrlNumber, signerType, signerConf,
                        caUris, numCrls, expirationPeriod);
    if (certBytes != null) {
      rv.setCert(X509Util.parseCert(certBytes));
    }

    if (cmpControl != null) {
      rv.setCmpControl(new CmpControl(cmpControl));
    }

    rv.setCmpResponderName(cmpResponderName);

    if (crlControl != null) {
      rv.setCrlControl(new CrlControl(crlControl));
    }

    rv.setCrlSignerName(crlSignerName);

    rv.setDuplicateKeyPermitted(duplicateKeyPermitted);
    rv.setDuplicateSubjectPermitted(duplicateSubjectPermitted);

    if (extraControl != null) {
      rv.setExtraControl(new ConfPairs(extraControl));
    }

    rv.setKeepExpiredCertInDays(keepExpiredCertInDays);

    rv.setMaxValidity(maxValidity);

    rv.setNextCrlNumber(nextCrlNumber);
    rv.setPermission(permission);
    rv.setProtocolSupport(protocolSupport);
    rv.setRevocationInfo(revocationInfo);
    rv.setSaveRequest(saveRequest);
    if (scepControl != null) {
      rv.setScepControl(new ScepControl(scepControl));
    }

    rv.setScepResponderName(scepResponderName);
    rv.setSerialNoBitLen(serialNoBitLen);
    rv.setSignerConf(signerConf);
    rv.setStatus(status);
    rv.setValidityMode(validityMode);

    return rv;
  }

}
