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

package org.xipki.ca.mgmt.conf;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xipki.util.conf.FileOrBinary;
import org.xipki.util.conf.FileOrValue;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class CaInfoType extends ValidatableConf {

  /**
   * If genSelfIssued is preset, it must be absent. Otherwise it specifies the CA certificate
   */
  private FileOrBinary cert;

  private boolean duplicateKey = true;

  private boolean duplicateSubject = true;

  private Integer expirationPeriod;

  private Map<String, String> extraControl;

  /**
   * A new self-issued CA certificate will be generated
   */
  private GenSelfIssuedType genSelfIssued;

  private Integer keepExpiredCertDays;

  private List<String> permissions;

  private String maxValidity;

  private Map<String, Object> cmpControl;

  private Map<String, Object> crlControl;

  private Map<String, Object> scepControl;

  private String cmpResponderName;

  private String scepResponderName;

  private String crlSignerName;

  private Set<String> protocolSupport;

  private boolean saveReq;

  private String signerType;

  private FileOrValue signerConf;

  private String status;

  /**
   * Valid values are strict, cutoff and lax. Default is strict
   */
  private String validityMode;

  private long nextCrlNo;

  private Integer numCrls;

  private int snSize;

  private CaUrisType caUris;

  public FileOrBinary getCert() {
    return cert;
  }

  public void setCert(FileOrBinary cert) {
    this.cert = cert;
  }

  public boolean isDuplicateKey() {
    return duplicateKey;
  }

  public void setDuplicateKey(boolean duplicateKey) {
    this.duplicateKey = duplicateKey;
  }

  public boolean isDuplicateSubject() {
    return duplicateSubject;
  }

  public void setDuplicateSubject(boolean duplicateSubject) {
    this.duplicateSubject = duplicateSubject;
  }

  public Integer getExpirationPeriod() {
    return expirationPeriod;
  }

  public void setExpirationPeriod(Integer expirationPeriod) {
    this.expirationPeriod = expirationPeriod;
  }

  public Map<String, String> getExtraControl() {
    return extraControl;
  }

  public void setExtraControl(Map<String, String> extraControl) {
    this.extraControl = extraControl;
  }

  public GenSelfIssuedType getGenSelfIssued() {
    return genSelfIssued;
  }

  public void setGenSelfIssued(GenSelfIssuedType genSelfIssued) {
    this.genSelfIssued = genSelfIssued;
  }

  public Integer getKeepExpiredCertDays() {
    return keepExpiredCertDays;
  }

  public void setKeepExpiredCertDays(Integer keepExpiredCertDays) {
    this.keepExpiredCertDays = keepExpiredCertDays;
  }

  public List<String> getPermissions() {
    if (permissions == null) {
      permissions = new LinkedList<>();
    }
    return permissions;
  }

  public void setPermissions(List<String> permissions) {
    this.permissions = permissions;
  }

  public String getMaxValidity() {
    return maxValidity;
  }

  public void setMaxValidity(String maxValidity) {
    this.maxValidity = maxValidity;
  }

  public Map<String, Object> getCmpControl() {
    return cmpControl;
  }

  public void setCmpControl(Map<String, Object> cmpControl) {
    this.cmpControl = cmpControl;
  }

  public Map<String, Object> getCrlControl() {
    return crlControl;
  }

  public void setCrlControl(Map<String, Object> crlControl) {
    this.crlControl = crlControl;
  }

  public Map<String, Object> getScepControl() {
    return scepControl;
  }

  public void setScepControl(Map<String, Object> scepControl) {
    this.scepControl = scepControl;
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

  public String getCrlSignerName() {
    return crlSignerName;
  }

  public void setCrlSignerName(String crlSignerName) {
    this.crlSignerName = crlSignerName;
  }

  public Set<String> getProtocolSupport() {
    return protocolSupport;
  }

  public void setProtocolSupport(Set<String> protocolSupport) {
    this.protocolSupport = protocolSupport;
  }

  public boolean isSaveReq() {
    return saveReq;
  }

  public void setSaveReq(boolean saveReq) {
    this.saveReq = saveReq;
  }

  public String getSignerType() {
    return signerType;
  }

  public void setSignerType(String signerType) {
    this.signerType = signerType;
  }

  public FileOrValue getSignerConf() {
    return signerConf;
  }

  public void setSignerConf(FileOrValue signerConf) {
    this.signerConf = signerConf;
  }

  public String getStatus() {
    return status;
  }

  public void setStatus(String status) {
    this.status = status;
  }

  public String getValidityMode() {
    return validityMode;
  }

  public void setValidityMode(String validityMode) {
    this.validityMode = validityMode;
  }

  public long getNextCrlNo() {
    return nextCrlNo;
  }

  public void setNextCrlNo(long nextCrlNo) {
    this.nextCrlNo = nextCrlNo;
  }

  public Integer getNumCrls() {
    return numCrls;
  }

  public void setNumCrls(Integer numCrls) {
    this.numCrls = numCrls;
  }

  public int getSnSize() {
    return snSize;
  }

  public void setSnSize(int snSize) {
    this.snSize = snSize;
  }

  public CaUrisType getCaUris() {
    return caUris;
  }

  public void setCaUris(CaUrisType caUris) {
    this.caUris = caUris;
  }

  @Override
  public void validate() throws InvalidConfException {
    if (genSelfIssued != null) {
      if (cert != null) {
        throw new InvalidConfException("cert and genSelfIssued may not be both non-null");
      }
    }
    validate(genSelfIssued);
    validate(cert);
    notEmpty(maxValidity, "maxValidity");
    notEmpty(protocolSupport, "protocolSupport");
    notEmpty(signerType, "signerType");
    notNull(signerConf, "signerConf");
    validate(signerConf);
    notEmpty(status, status);
    validate(caUris);
  }

}
