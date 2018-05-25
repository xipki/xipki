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

package org.xipki.ca.server.mgmt.api;

import java.security.cert.X509Certificate;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ChangeCaEntry {

  private final NameId ident;

  private CaStatus status;

  private CertValidity maxValidity;

  private String signerType;

  private String signerConf;

  private String cmpControl;

  private String crlControl;

  private String scepControl;

  private String cmpResponderName;

  private String scepResponderName;

  private String crlSignerName;

  private Boolean duplicateKeyPermitted;

  private Boolean duplicateSubjectPermitted;

  private Boolean supportCmp;

  private Boolean supportRest;

  private Boolean supportScep;

  private Boolean saveRequest;

  private ValidityMode validityMode;

  private Integer permission;

  private Integer keepExpiredCertInDays;

  private Integer expirationPeriod;

  private ConfPairs extraControl;

  private CaUris caUris;

  private X509Certificate cert;

  private Integer numCrls;

  private Integer serialNoBitLen;

  public ChangeCaEntry(NameId ident) throws CaMgmtException {
    this.ident = ParamUtil.requireNonNull("ident", ident);
  }

  public NameId getIdent() {
    return ident;
  }

  public CaStatus getStatus() {
    return status;
  }

  public void setStatus(CaStatus status) {
    this.status = status;
  }

  public CertValidity getMaxValidity() {
    return maxValidity;
  }

  public void setMaxValidity(CertValidity maxValidity) {
    this.maxValidity = maxValidity;
  }

  public String getSignerType() {
    return signerType;
  }

  public void setSignerType(String signerType) {
    this.signerType = signerType == null ? null : signerType.toLowerCase();
  }

  public String getSignerConf() {
    return signerConf;
  }

  public void setSignerConf(String signerConf) {
    this.signerConf = signerConf;
  }

  public String getCmpControl() {
    return cmpControl;
  }

  public void setCmpControl(String cmpControl) {
    this.cmpControl = cmpControl;
  }

  public String getCrlControl() {
    return crlControl;
  }

  public void setCrlControl(String crlControl) {
    this.crlControl = crlControl;
  }

  public String getScepControl() {
    return scepControl;
  }

  public void setScepControl(String scepControl) {
    this.scepControl = scepControl;
  }

  public String getCmpResponderName() {
    return cmpResponderName;
  }

  public void setCmpResponderName(String responderName) {
    this.cmpResponderName = (responderName == null) ? null : responderName.toLowerCase();
  }

  public String getScepResponderName() {
    return scepResponderName;
  }

  public void setScepResponderName(String responderName) {
    this.scepResponderName = (responderName == null) ? null : responderName.toLowerCase();
  }

  public String getCrlSignerName() {
    return crlSignerName;
  }

  public void setCrlSignerName(String crlSignerName) {
    this.crlSignerName = (crlSignerName == null) ? null : crlSignerName.toLowerCase();
  }

  public Boolean getDuplicateKeyPermitted() {
    return duplicateKeyPermitted;
  }

  public void setDuplicateKeyPermitted(Boolean duplicateKeyPermitted) {
    this.duplicateKeyPermitted = duplicateKeyPermitted;
  }

  public Boolean getDuplicateSubjectPermitted() {
    return duplicateSubjectPermitted;
  }

  public void setDuplicateSubjectPermitted(Boolean duplicateSubjectPermitted) {
    this.duplicateSubjectPermitted = duplicateSubjectPermitted;
  }

  public ValidityMode getValidityMode() {
    return validityMode;
  }

  public void setValidityMode(ValidityMode validityMode) {
    this.validityMode = validityMode;
  }

  public Boolean getSupportCmp() {
    return supportCmp;
  }

  public void setSupportCmp(Boolean supportCmp) {
    this.supportCmp = supportCmp;
  }

  public Boolean getSupportRest() {
    return supportRest;
  }

  public void setSupportRest(Boolean supportRest) {
    this.supportRest = supportRest;
  }

  public Boolean getSupportScep() {
    return supportScep;
  }

  public void setSupportScep(Boolean supportScep) {
    this.supportScep = supportScep;
  }

  public Boolean getSaveRequest() {
    return saveRequest;
  }

  public void setSaveRequest(Boolean saveRequest) {
    this.saveRequest = saveRequest;
  }

  public Integer getPermission() {
    return permission;
  }

  public void setPermission(Integer permission) {
    this.permission = permission;
  }

  public Integer getExpirationPeriod() {
    return expirationPeriod;
  }

  public void setExpirationPeriod(Integer expirationPeriod) {
    this.expirationPeriod = expirationPeriod;
  }

  public Integer getKeepExpiredCertInDays() {
    return keepExpiredCertInDays;
  }

  public void setKeepExpiredCertInDays(Integer days) {
    this.keepExpiredCertInDays = days;
  }

  public ConfPairs getExtraControl() {
    return extraControl;
  }

  public void setExtraControl(ConfPairs extraControl) {
    this.extraControl = extraControl;
  }

  public Integer getSerialNoBitLen() {
    return serialNoBitLen;
  }

  public void setSerialNoBitLen(Integer serialNoBitLen) {
    if (serialNoBitLen != null) {
      ParamUtil.requireRange("serialNoBitLen", serialNoBitLen, 63, 159);
    }
    this.serialNoBitLen = serialNoBitLen;
  }

  public CaUris getCaUris() {
    return caUris;
  }

  public void setCaUris(CaUris caUris) {
    this.caUris = caUris;
  }

  public X509Certificate getCert() {
    return cert;
  }

  public void setCert(X509Certificate cert) {
    this.cert = cert;
  }

  public Integer getNumCrls() {
    return numCrls;
  }

  public void setNumCrls(Integer numCrls) {
    this.numCrls = numCrls;
  }

}
