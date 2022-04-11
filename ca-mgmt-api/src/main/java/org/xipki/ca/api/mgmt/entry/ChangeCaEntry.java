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

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.ValidityMode;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.Validity;

import java.util.List;

/**
 * Management Entry Change CA.
 * @author Lijun Liao
 *
 */

public class ChangeCaEntry extends MgmtEntry {

  private NameId ident;

  private CaStatus status;

  private Validity maxValidity;

  private String signerType;

  private String signerConf;

  private String cmpControl;

  private String crlControl;

  private String scepControl;

  private String ctlogControl;

  private String popoControl;

  private String revokeSuspendedControl;

  private String cmpResponderName;

  private String scepResponderName;

  private String crlSignerName;

  private List<String> keypairGenNames;

  private Boolean supportCmp;

  private Boolean supportRest;

  private Boolean supportScep;

  private Boolean saveCert;

  private Boolean saveRequest;

  private Boolean saveKeypair;

  private ValidityMode validityMode;

  private Integer permission;

  private Integer keepExpiredCertInDays;

  private Integer expirationPeriod;

  private String extraControl;

  private CaUris caUris;

  private byte[] encodedCert;

  private List<byte[]> encodedCertchain;

  private Integer numCrls;

  private Integer serialNoLen;

  // For the deserialization only
  @SuppressWarnings("unused")
  private ChangeCaEntry() {
  }

  public ChangeCaEntry(NameId ident) {
    this.ident = Args.notNull(ident, "ident");
  }

  public void setIdent(NameId ident) {
    this.ident = Args.notNull(ident, "ident");
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

  public Validity getMaxValidity() {
    return maxValidity;
  }

  public void setMaxValidity(Validity maxValidity) {
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

  public String getCtlogControl() {
    return ctlogControl;
  }

  public void setCtlogControl(String ctlogControl) {
    this.ctlogControl = ctlogControl;
  }

  public String getRevokeSuspendedControl() {
    return revokeSuspendedControl;
  }

  public void setRevokeSuspendedControl(String revokeSuspendedControl) {
    this.revokeSuspendedControl = revokeSuspendedControl;
  }

  public String getPopoControl() {
    return popoControl;
  }

  public void setPopoControl(String popoControl) {
    this.popoControl = popoControl;
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

  public List<String> getKeypairGenNames() {
    return keypairGenNames;
  }

  public void setKeypairGenNames(List<String> keypairGenNames) {
    this.keypairGenNames = (keypairGenNames == null)
            ? null : CollectionUtil.toLowerCaseList(keypairGenNames);
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

  public Boolean getSaveCert() {
    return saveCert;
  }

  public void setSaveCert(Boolean saveCert) {
    this.saveCert = saveCert;
  }

  public Boolean getSaveRequest() {
    return saveRequest;
  }

  public void setSaveRequest(Boolean saveRequest) {
    this.saveRequest = saveRequest;
  }

  public Boolean getSaveKeypair() {
    return saveKeypair;
  }

  public void setSaveKeypair(Boolean saveKeypair) {
    this.saveKeypair = saveKeypair;
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

  public String getExtraControl() {
    return extraControl;
  }

  public void setExtraControl(String extraControl) {
    this.extraControl = extraControl;
  }

  public Integer getSerialNoLen() {
    return serialNoLen;
  }

  public void setSerialNoLen(Integer serialNoLen) {
    if (serialNoLen != null) {
      Args.range(serialNoLen, "serialNoLen",
          CaManager.MIN_SERIALNUMBER_SIZE, CaManager.MAX_SERIALNUMBER_SIZE);
    }
    this.serialNoLen = serialNoLen;
  }

  public CaUris getCaUris() {
    return caUris;
  }

  public void setCaUris(CaUris caUris) {
    this.caUris = caUris;
  }

  public byte[] getEncodedCert() {
    return encodedCert;
  }

  public void setEncodedCert(byte[] encodedCert) {
    this.encodedCert = encodedCert;
  }

  public List<byte[]> getEncodedCertchain() {
    return encodedCertchain;
  }

  public void setEncodedCertchain(List<byte[]> encodedCertchain) {
    this.encodedCertchain = encodedCertchain;
  }

  public Integer getNumCrls() {
    return numCrls;
  }

  public void setNumCrls(Integer numCrls) {
    this.numCrls = numCrls;
  }

}
