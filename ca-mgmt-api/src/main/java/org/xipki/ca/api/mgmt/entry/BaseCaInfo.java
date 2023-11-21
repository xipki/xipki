// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.mgmt.*;
import org.xipki.security.CertRevocationInfo;
import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;

import java.util.List;

/**
 * This class fields of a single CA, which are common of different real CA classes.
 *
 * @author Lijun Liao (xipki)
 */

public abstract class BaseCaInfo extends MgmtEntry {

  protected CaUris caUris;

  protected String crlSignerName;

  protected int expirationPeriod = 365; // days

  protected int keepExpiredCertDays = -1; // keep forever

  protected List<String> keypairGenNames;

  protected long nextCrlNo;

  protected Validity maxValidity;

  protected int numCrls = 30;

  protected CertRevocationInfo revocationInfo;

  protected boolean saveCert = true;

  protected boolean saveKeypair = false;

  protected String signerType;

  protected int snSize = 20;

  protected CaStatus status = CaStatus.active;

  protected Permissions permissions;

  protected CrlControl crlControl;

  protected CtlogControl ctlogControl;

  protected RevokeSuspendedControl revokeSuspendedControl;

  protected ConfPairs extraControl;

  /**
   * Valid values are strict, cutoff and lax. Default is strict
   */
  protected ValidityMode validityMode = ValidityMode.strict;

  public final CaUris getCaUris() {
    return caUris;
  }

  public final void setCaUris(CaUris caUris) {
    this.caUris = caUris;
  }

  public final String getCrlSignerName() {
    return crlSignerName;
  }

  public final void setCrlSignerName(String crlSignerName) {
    this.crlSignerName = StringUtil.lowercase(crlSignerName);
  }

  public final int getExpirationPeriod() {
    return expirationPeriod;
  }

  public final void setExpirationPeriod(int expirationPeriod) {
    this.expirationPeriod = expirationPeriod;
  }

  public int getKeepExpiredCertDays() {
    return keepExpiredCertDays;
  }

  public void setKeepExpiredCertDays(int keepExpiredCertDays) {
    this.keepExpiredCertDays = keepExpiredCertDays;
  }

  public final List<String> getKeypairGenNames() {
    return keypairGenNames;
  }

  public final void setKeypairGenNames(List<String> keypairGenNames) {
    this.keypairGenNames = StringUtil.lowercase(keypairGenNames);
  }

  public final long getNextCrlNo() {
    return nextCrlNo;
  }

  public final void setNextCrlNo(long nextCrlNo) {
    this.nextCrlNo = nextCrlNo;
  }

  public final Validity getMaxValidity() {
    return maxValidity;
  }

  public final void setMaxValidity(Validity maxValidity) {
    this.maxValidity = maxValidity;
  }

  public final int getNumCrls() {
    return numCrls;
  }

  public final void setNumCrls(int numCrls) {
    this.numCrls = numCrls;
  }

  public final CertRevocationInfo getRevocationInfo() {
    return revocationInfo;
  }

  public final void setRevocationInfo(CertRevocationInfo revocationInfo) {
    this.revocationInfo = revocationInfo;
  }

  public final boolean isSaveCert() {
    return saveCert;
  }

  public final void setSaveCert(boolean saveCert) {
    this.saveCert = saveCert;
  }

  public final boolean isSaveKeypair() {
    return saveKeypair;
  }

  public final void setSaveKeypair(boolean saveKeypair) {
    this.saveKeypair = saveKeypair;
  }

  public final String getSignerType() {
    return signerType;
  }

  public final void setSignerType(String signerType) {
    this.signerType = signerType;
  }

  public final int getSnSize() {
    return snSize;
  }

  public final void setSnSize(int snSize) {
    if (snSize > CaManager.MAX_SERIALNUMBER_SIZE) {
      this.snSize = CaManager.MAX_SERIALNUMBER_SIZE;
    } else this.snSize = Math.max(snSize, CaManager.MIN_SERIALNUMBER_SIZE);
  }

  public final CaStatus getStatus() {
    return status;
  }

  public final void setStatus(CaStatus status) {
    this.status = status;
  }

  public final ValidityMode getValidityMode() {
    return validityMode;
  }

  public final void setValidityMode(ValidityMode validityMode) {
    this.validityMode = validityMode;
  }

  public Permissions getPermissions() {
    return permissions;
  }

  public void setPermissions(Permissions permissions) {
    this.permissions = permissions;
  }

  public final CrlControl getCrlControl() {
    return crlControl;
  }

  public final void setCrlControl(CrlControl crlControl) {
    this.crlControl = crlControl;
  }

  public final CtlogControl getCtlogControl() {
    return ctlogControl;
  }

  public final void setCtlogControl(CtlogControl ctlogControl) {
    this.ctlogControl = ctlogControl;
  }

  public final RevokeSuspendedControl getRevokeSuspendedControl() {
    return revokeSuspendedControl;
  }

  public final void setRevokeSuspendedControl(RevokeSuspendedControl revokeSuspendedControl) {
    this.revokeSuspendedControl = revokeSuspendedControl;
  }

  public final ConfPairs getExtraControl() {
    return extraControl;
  }

  public final void setExtraControl(ConfPairs extraControl) {
    this.extraControl = extraControl;
  }

  @Override
  public void validate() throws InvalidConfException {
    notNull(maxValidity, "maxValidity");
    notBlank(signerType, "signerType");
    notNull(status, "status");
  }

  protected boolean equals(BaseCaInfo obj, boolean ignoreDynamicFields) {
    if (!ignoreDynamicFields) {
      if (nextCrlNo != obj.nextCrlNo) {
        return false;
      }
    }

    return CompareUtil.equalsObject(caUris, obj.caUris)
        && CompareUtil.equalsObject(crlSignerName, obj.crlSignerName)
        && (expirationPeriod == obj.expirationPeriod)
        && (keepExpiredCertDays == obj.keepExpiredCertDays)
        && CompareUtil.equalsObject(keypairGenNames, obj.keypairGenNames)
        && CompareUtil.equalsObject(maxValidity, obj.maxValidity)
        && (numCrls == obj.numCrls)
        && CompareUtil.equalsObject(revocationInfo, obj.revocationInfo)
        && (saveCert == obj.saveCert)
        && (saveKeypair == obj.saveKeypair)
        && signerType.equals(obj.signerType)
        && (snSize == obj.snSize)
        && CompareUtil.equalsObject(status, obj.status)
        && CompareUtil.equalsObject(validityMode, obj.validityMode)
        && CompareUtil.equalsObject(permissions, obj.permissions)
        && CompareUtil.equalsObject(crlControl, obj.crlControl)
        && CompareUtil.equalsObject(ctlogControl, obj.ctlogControl)
        && CompareUtil.equalsObject(extraControl, obj.extraControl)
        && CompareUtil.equalsObject(revokeSuspendedControl, obj.revokeSuspendedControl);
  }

  public void copyBaseInfoTo(BaseCaInfo dest) {
    dest.nextCrlNo = nextCrlNo;
    dest.caUris = caUris;
    if (caUris == null) {
      dest.caUris = CaUris.EMPTY_INSTANCE;
    }

    dest.crlSignerName = crlSignerName;
    dest.expirationPeriod = expirationPeriod;
    dest.keepExpiredCertDays = keepExpiredCertDays;
    dest.keypairGenNames = keypairGenNames;
    dest.maxValidity = maxValidity;
    dest.numCrls = numCrls;
    dest.revocationInfo = revocationInfo;
    dest.saveCert = saveCert;
    dest.saveKeypair = saveKeypair;
    dest.signerType = signerType;
    dest.snSize = snSize;
    dest.status = status;
    dest.validityMode = validityMode;

    dest.permissions = permissions;
    dest.crlControl = crlControl;
    dest.ctlogControl = ctlogControl;
    dest.revokeSuspendedControl = revokeSuspendedControl;
    dest.extraControl = extraControl;
  }

}
