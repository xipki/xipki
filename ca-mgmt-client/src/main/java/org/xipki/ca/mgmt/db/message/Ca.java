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

package org.xipki.ca.mgmt.db.message;

import org.xipki.util.conf.FileOrBinary;
import org.xipki.util.conf.FileOrValue;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class Ca extends ValidatableConf {

  private int id;

  private String name;

  private int snSize;

  private long nextCrlNo;

  private String status;

  private String caUris;

  private String maxValidity;

  private FileOrBinary cert;

  private String signerType;

  private FileOrValue signerConf;

  private String crlSignerName;

  private String cmpResponderName;

  private String scepResponderName;

  private String cmpControl;

  private String scepControl;

  private String crlControl;

  private int duplicateKey;

  private int duplicateSubject;

  private String protocolSupport;

  private int saveReq;

  private int permission;

  private int numCrls;

  private int expirationPeriod;

  private int keepExpiredCertDays;

  private String revInfo;

  private String validityMode;

  private String extraControl;

  public int getId() {
    return id;
  }

  public void setId(int id) {
    this.id = id;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public int getSnSize() {
    return snSize;
  }

  public void setSnSize(int snSize) {
    this.snSize = snSize;
  }

  public long getNextCrlNo() {
    return nextCrlNo;
  }

  public void setNextCrlNo(long nextCrlNo) {
    this.nextCrlNo = nextCrlNo;
  }

  public String getStatus() {
    return status;
  }

  public void setStatus(String status) {
    this.status = status;
  }

  public String getCaUris() {
    return caUris;
  }

  public void setCaUris(String caUris) {
    this.caUris = caUris;
  }

  public String getMaxValidity() {
    return maxValidity;
  }

  public void setMaxValidity(String maxValidity) {
    this.maxValidity = maxValidity;
  }

  public FileOrBinary getCert() {
    return cert;
  }

  public void setCert(FileOrBinary cert) {
    this.cert = cert;
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

  public String getCrlSignerName() {
    return crlSignerName;
  }

  public void setCrlSignerName(String crlSignerName) {
    this.crlSignerName = crlSignerName;
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

  public String getCmpControl() {
    return cmpControl;
  }

  public void setCmpControl(String cmpControl) {
    this.cmpControl = cmpControl;
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

  public int getDuplicateKey() {
    return duplicateKey;
  }

  public void setDuplicateKey(int duplicateKey) {
    this.duplicateKey = duplicateKey;
  }

  public int getDuplicateSubject() {
    return duplicateSubject;
  }

  public void setDuplicateSubject(int duplicateSubject) {
    this.duplicateSubject = duplicateSubject;
  }

  public String getProtocolSupport() {
    return protocolSupport;
  }

  public void setProtocolSupport(String protocolSupport) {
    this.protocolSupport = protocolSupport;
  }

  public int getSaveReq() {
    return saveReq;
  }

  public void setSaveReq(int saveReq) {
    this.saveReq = saveReq;
  }

  public int getPermission() {
    return permission;
  }

  public void setPermission(int permission) {
    this.permission = permission;
  }

  public int getNumCrls() {
    return numCrls;
  }

  public void setNumCrls(int numCrls) {
    this.numCrls = numCrls;
  }

  public int getExpirationPeriod() {
    return expirationPeriod;
  }

  public void setExpirationPeriod(int expirationPeriod) {
    this.expirationPeriod = expirationPeriod;
  }

  public int getKeepExpiredCertDays() {
    return keepExpiredCertDays;
  }

  public void setKeepExpiredCertDays(int keepExpiredCertDays) {
    this.keepExpiredCertDays = keepExpiredCertDays;
  }

  public String getRevInfo() {
    return revInfo;
  }

  public void setRevInfo(String revInfo) {
    this.revInfo = revInfo;
  }

  public String getValidityMode() {
    return validityMode;
  }

  public void setValidityMode(String validityMode) {
    this.validityMode = validityMode;
  }

  public String getExtraControl() {
    return extraControl;
  }

  public void setExtraControl(String extraControl) {
    this.extraControl = extraControl;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(name, "name");
    notEmpty(status, "status");
    notEmpty(maxValidity, "maxValidity");

    notNull(cert, "cert");
    cert.validate();

    notEmpty(signerType, "signerType");

    notNull(signerConf, "signerConf");
    signerConf.validate();

    notEmpty(protocolSupport, "protocolSupport");
  }

}
