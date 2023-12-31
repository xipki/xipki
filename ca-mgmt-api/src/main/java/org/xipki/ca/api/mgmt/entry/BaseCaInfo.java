// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.CtlogControl;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.RevokeSuspendedControl;
import org.xipki.ca.api.mgmt.ValidityMode;
import org.xipki.security.CertRevocationInfo;
import org.xipki.util.CompareUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;
import org.xipki.util.Validity;
import org.xipki.util.exception.InvalidConfException;

import java.util.List;

/**
 * This class fields of a single CA, which are common of different real CA classes.
 *
 * @author Lijun Liao (xipki)
 */

public abstract class BaseCaInfo extends MgmtEntry {

  private CaUris caUris;

  private String crlSignerName;

  private int expirationPeriod = 365; // days

  private int keepExpiredCertDays = -1; // keep forever

  private List<String> keypairGenNames;

  private long nextCrlNo;

  private Validity maxValidity;

  private int numCrls = 30;

  private CertRevocationInfo revocationInfo;

  private boolean saveCert = true;

  private boolean saveKeypair = false;

  private String signerType;

  private int snSize = 20;

  private CaStatus status = CaStatus.active;

  private Permissions permissions;

  private CrlControl crlControl;

  private CtlogControl ctlogControl;

  private RevokeSuspendedControl revokeSuspendedControl;

  private ConfPairs extraControl;

  /**
   * Valid values are strict, cutoff and lax. Default is strict
   */
  private ValidityMode validityMode = ValidityMode.strict;

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

  protected String toString(boolean verbose) {
    String extraCtrlText;
    if (extraControl == null) {
      extraCtrlText = "-";
    } else {
      extraCtrlText = extraControl.getEncoded();
      if (!verbose && extraCtrlText.length() > 100) {
        extraCtrlText = StringUtil.concat(extraCtrlText.substring(0, 97), "...");
      }
    }

    String revInfoText = "";
    if (revocationInfo != null) {
      revInfoText = StringUtil.concatObjectsCap(30,
          "\n\treason: ", revocationInfo.getReason().getDescription(),
          "\n\trevoked at ", revocationInfo.getRevocationTime());
    }

    return StringUtil.concatObjectsCap(1500,
        "\nsigner type:          ", signerType,
        "\nstatus:               ", (status == null ? "-" : status.getStatus()),
        "\nmax. validity:        ", maxValidity,
        "\nexpiration period:    ", expirationPeriod, "d",
        "\nCRL signer name:      ", (crlSignerName == null ? "-" : crlSignerName),
        "\nsave certificate:     ", saveCert,
        "\nsave keypair:         ", saveKeypair,
        "\nvalidity mode:        ", validityMode,
        "\npermission:           ", permissions,
        "\nkeep expired certs:   ", (keepExpiredCertDays < 0 ? "forever" : keepExpiredCertDays + " days"),
        "\nextra control:        ", extraCtrlText,
        "\nserial number length: ", snSize, " bytes",
        "\nrevocation:           ", (revocationInfo == null ? "not revoked" : "revoked"), revInfoText,
        "\nnext CRL number:      ", nextCrlNo,
        "\nKeyPair generation names: ", (keypairGenNames == null ? "-" : keypairGenNames),
        "\n", getCaUris(),
        "\nCRL control:\n", (crlControl == null ? "  -" : crlControl.toString(verbose)),
        "\nCTLog control:\n", (ctlogControl == null ? "  -" : ctlogControl.toString(verbose)),
        "\nrevoke suspended certificates control: \n",
            (revokeSuspendedControl == null ? "  -" : revokeSuspendedControl.toString(verbose)));
  }

}
