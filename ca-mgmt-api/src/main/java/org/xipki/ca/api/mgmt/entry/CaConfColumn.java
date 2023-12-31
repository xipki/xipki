// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.mgmt.CaJson;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.CtlogControl;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.RevokeSuspendedControl;
import org.xipki.ca.api.mgmt.ValidityMode;
import org.xipki.util.ConfPairs;
import org.xipki.util.Validity;

import java.util.List;

/**
 * Represent the CONF column in the table CA.
 *
 * @author Lijun Liao (xipki)
 */
public class CaConfColumn {

  public static final int DEFAULT_numCrls = 30;

  public static final int DEFAULT_expirationPeriod = 365;

  public static final int DEFAULT_keepExpiredCertDays = -1;

  /**
   * Syntax version.
   */
  private int version = 1;

  /**
   * number of octets of the serial number.
   */
  private int snSize;

  private List<String> cacertUris;

  private List<String> ocspUris;

  private List<String> crlUris;

  private List<String> deltaCrlUris;

  /**
   * Not nullable. Maximal validity of the generated certificates.
   */
  private Validity maxValidity;

  private CrlControl crlControl;

  /**
   * Certificate Transparency Log Control.
   */
  private CtlogControl ctlogControl;

  private RevokeSuspendedControl revokeSuspendedControl;

  private List<String> keypairGenNames;

  /**
   * Whether to save the certificate, default is true.
   */
  private boolean saveCert;

  /**
   * Whether the generated keypair should be saved, default is false.
   */
  private boolean saveKeypair;

  private ValidityMode validityMode;

  private Permissions permission;

  private int numCrls = DEFAULT_numCrls;

  private int expirationPeriod = DEFAULT_expirationPeriod;

  /**
   * How long in days should certificates be kept after the expiration.
   * Negative value for kept-for-ever.
   */
  private int keepExpiredCertDays = DEFAULT_keepExpiredCertDays;

  /**
   * Extra control.
   */
  private ConfPairs extraControl;

  public int getVersion() {
    return version;
  }

  public void setVersion(int version) {
    this.version = version;
  }

  public int getSnSize() {
    return snSize;
  }

  public void setSnSize(int snSize) {
    this.snSize = snSize;
  }

  public List<String> getCacertUris() {
    return cacertUris;
  }

  public void setCacertUris(List<String> cacertUris) {
    this.cacertUris = cacertUris;
  }

  public List<String> getOcspUris() {
    return ocspUris;
  }

  public void setOcspUris(List<String> ocspUris) {
    this.ocspUris = ocspUris;
  }

  public List<String> getCrlUris() {
    return crlUris;
  }

  public void setCrlUris(List<String> crlUris) {
    this.crlUris = crlUris;
  }

  public List<String> getDeltaCrlUris() {
    return deltaCrlUris;
  }

  public void setDeltaCrlUris(List<String> deltaCrlUris) {
    this.deltaCrlUris = deltaCrlUris;
  }

  public Validity getMaxValidity() {
    return maxValidity;
  }

  public void setMaxValidity(Validity maxValidity) {
    this.maxValidity = maxValidity;
  }

  public List<String> getKeypairGenNames() {
    return keypairGenNames;
  }

  public void setKeypairGenNames(List<String> keypairGenNames) {
    this.keypairGenNames = keypairGenNames;
  }

  public boolean isSaveCert() {
    return saveCert;
  }

  public void setSaveCert(boolean saveCert) {
    this.saveCert = saveCert;
  }

  public boolean isSaveKeypair() {
    return saveKeypair;
  }

  public void setSaveKeypair(boolean saveKeypair) {
    this.saveKeypair = saveKeypair;
  }

  public ValidityMode getValidityMode() {
    return validityMode;
  }

  public void setValidityMode(ValidityMode validityMode) {
    this.validityMode = validityMode;
  }

  public Permissions getPermission() {
    return permission;
  }

  public void setPermission(Permissions permission) {
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

  public CrlControl getCrlControl() {
    return crlControl;
  }

  public void setCrlControl(CrlControl crlControl) {
    this.crlControl = crlControl;
  }

  public CtlogControl getCtlogControl() {
    return ctlogControl;
  }

  public void setCtlogControl(CtlogControl ctlogControl) {
    this.ctlogControl = ctlogControl;
  }

  public RevokeSuspendedControl getRevokeSuspendedControl() {
    return revokeSuspendedControl;
  }

  public void setRevokeSuspendedControl(RevokeSuspendedControl revokeSuspendedControl) {
    this.revokeSuspendedControl = revokeSuspendedControl;
  }

  public ConfPairs getExtraControl() {
    return extraControl;
  }

  public void setExtraControl(ConfPairs extraControl) {
    this.extraControl = extraControl;
  }

  public CaConfColumn copy() {
    return decode(encode());
  }

  public static CaConfColumn decode(String encoded) {
    return CaJson.parseObject(encoded, CaConfColumn.class);
  }

  public void fillBaseCaInfo(BaseCaInfo baseCaInfo) throws CaMgmtException {
    baseCaInfo.setCaUris(caUris());
    baseCaInfo.setExpirationPeriod(expirationPeriod);
    baseCaInfo.setKeepExpiredCertDays(keepExpiredCertDays);
    baseCaInfo.setKeypairGenNames(keypairGenNames);
    baseCaInfo.setMaxValidity(maxValidity);
    baseCaInfo.setNumCrls(numCrls);
    baseCaInfo.setSaveCert(saveCert);
    baseCaInfo.setSnSize(snSize);
    baseCaInfo.setSaveKeypair(saveKeypair);
    baseCaInfo.setValidityMode(validityMode());

    baseCaInfo.setPermissions(permission);
    baseCaInfo.setCrlControl(crlControl);
    baseCaInfo.setCtlogControl(ctlogControl);
    baseCaInfo.setExtraControl(extraControl);
    baseCaInfo.setRevokeSuspendedControl(revokeSuspendedControl);
  }

  public static CaConfColumn fromBaseCaInfo(BaseCaInfo baseCaInfo) {
    CaConfColumn cc = new CaConfColumn();

    // CA URIS
    CaUris caUris = baseCaInfo.getCaUris();
    if (caUris != null) {
      cc.setCacertUris(caUris.getCacertUris());
      cc.setCrlUris(caUris.getCrlUris());
      cc.setDeltaCrlUris(caUris.getDeltaCrlUris());
      cc.setOcspUris(caUris.getOcspUris());
    }

    cc.setKeypairGenNames(baseCaInfo.getKeypairGenNames());
    cc.setMaxValidity(baseCaInfo.getMaxValidity());
    cc.setNumCrls(baseCaInfo.getNumCrls());
    cc.setSaveCert(baseCaInfo.isSaveCert());
    cc.setSaveKeypair(baseCaInfo.isSaveKeypair());
    cc.setSnSize(baseCaInfo.getSnSize());
    cc.setValidityMode(baseCaInfo.getValidityMode());
    cc.setExpirationPeriod(baseCaInfo.getExpirationPeriod());
    cc.setKeepExpiredCertDays(baseCaInfo.getKeepExpiredCertDays());

    cc.setPermission(baseCaInfo.getPermissions());
    cc.setCtlogControl(baseCaInfo.getCtlogControl());
    cc.setCrlControl(baseCaInfo.getCrlControl());
    cc.setRevokeSuspendedControl(baseCaInfo.getRevokeSuspendedControl());
    cc.setExtraControl(baseCaInfo.getExtraControl());

    return cc;
  }

  public String encode() {
    return CaJson.toPrettyJson(this);
  }

  public CaUris caUris() {
    return new CaUris(cacertUris, ocspUris, crlUris, deltaCrlUris);
  }

  private ValidityMode validityMode() {
    return validityMode == null ? ValidityMode.strict : validityMode;
  }

}
