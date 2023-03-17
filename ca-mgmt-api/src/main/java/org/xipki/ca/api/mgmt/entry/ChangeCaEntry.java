// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

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
 * @author Lijun Liao (xipki)
 *
 */

public class ChangeCaEntry extends MgmtEntry {

  private NameId ident;

  private CaStatus status;

  private Validity maxValidity;

  private String signerType;

  private String signerConf;

  private String crlControl;

  private String ctlogControl;

  private String revokeSuspendedControl;

  private String crlSignerName;

  private List<String> keypairGenNames;

  private Boolean saveCert;

  private Boolean saveKeypair;

  private Boolean uniqueKey;

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

  public String getCrlControl() {
    return crlControl;
  }

  public void setCrlControl(String crlControl) {
    this.crlControl = crlControl;
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
    this.keypairGenNames = (keypairGenNames == null) ? null : CollectionUtil.toLowerCaseList(keypairGenNames);
  }

  public ValidityMode getValidityMode() {
    return validityMode;
  }

  public void setValidityMode(ValidityMode validityMode) {
    this.validityMode = validityMode;
  }

  public Boolean getSaveCert() {
    return saveCert;
  }

  public void setSaveCert(Boolean saveCert) {
    this.saveCert = saveCert;
  }

  public Boolean getSaveKeypair() {
    return saveKeypair;
  }

  public void setSaveKeypair(Boolean saveKeypair) {
    this.saveKeypair = saveKeypair;
  }

  public Boolean getUniqueKey() {
    return uniqueKey;
  }

  public void setUniqueKey(Boolean uniqueKey) {
    this.uniqueKey = uniqueKey;
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
      Args.range(serialNoLen, "serialNoLen", CaManager.MIN_SERIALNUMBER_SIZE, CaManager.MAX_SERIALNUMBER_SIZE);
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
