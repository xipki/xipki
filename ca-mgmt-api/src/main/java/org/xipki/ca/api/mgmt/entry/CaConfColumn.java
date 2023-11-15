// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.mgmt.*;
import org.xipki.util.ConfPairs;
import org.xipki.util.PermissionConstants;
import org.xipki.util.Validity;
import org.xipki.util.exception.InvalidConfException;

import java.util.List;
import java.util.Map;

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

  private Map<String,String> crlControl;

  /**
   * Certificate Transparency Log Control.
   */
  private Map<String,String> ctlogControl;

  private Map<String,String> revokeSuspendedControl;

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

  private int permission;

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
  private Map<String, String> extraControl;

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

  public Map<String, String> getCrlControl() {
    return crlControl;
  }

  public void setCrlControl(Map<String, String> crlControl) {
    this.crlControl = crlControl;
  }

  public Map<String, String> getCtlogControl() {
    return ctlogControl;
  }

  public void setCtlogControl(Map<String, String> ctlogControl) {
    this.ctlogControl = ctlogControl;
  }

  public Map<String, String> getRevokeSuspendedControl() {
    return revokeSuspendedControl;
  }

  public void setRevokeSuspendedControl(Map<String, String> revokeSuspendedControl) {
    this.revokeSuspendedControl = revokeSuspendedControl;
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

  public Map<String, String> getExtraControl() {
    return extraControl;
  }

  public void setExtraControl(Map<String, String> extraControl) {
    this.extraControl = extraControl;
  }

  public CaConfColumn copy() {
    return decode(encode());
  }

  public static CaConfColumn decode(String encoded) {
    return CaJson.parseObject(encoded, CaConfColumn.class);
  }

  public void fillCaEntry(CaEntry entry) throws CaMgmtException {
    fillBaseCaInfo(entry);

    entry.setPermission(permission);
    entry.setCrlControl(crlControl());
    entry.setCtlogControl(ctlogControl());
    entry.setExtraControl(extraControl());
    entry.setRevokeSuspendedControl(revokeSuspendedControl());
  }

  public void fillCaConf(CaConfType.Ca ca) {
    CaConfType.CaInfo caInfo = ca.getCaInfo();
    fillBaseCaInfo(caInfo);

    caInfo.setPermissions(PermissionConstants.permissionToStringList(permission));
    caInfo.setCrlControl(crlControl);
    caInfo.setCtlogControl(ctlogControl);
    caInfo.setExtraControl(extraControl);
    caInfo.setRevokeSuspendedControl(revokeSuspendedControl);
  }

  private void fillBaseCaInfo(BaseCaInfo entry) {
    entry.setCaUris(caUris());
    entry.setExpirationPeriod(expirationPeriod);
    entry.setKeepExpiredCertDays(keepExpiredCertDays);
    entry.setKeypairGenNames(keypairGenNames);
    entry.setMaxValidity(maxValidity());
    entry.setNumCrls(numCrls);
    entry.setSaveCert(saveCert);
    entry.setSnSize(snSize);
    entry.setSaveKeypair(saveKeypair);
    entry.setValidityMode(validityMode());
  }

  public static CaConfColumn fromCaEntry(CaEntry caEntry) {
    CaConfColumn cc = fromBaseCaInfo(caEntry);

    cc.setPermission(caEntry.getPermission());

    // CRL Control
    CrlControl crlControl = caEntry.getCrlControl();
    if (crlControl != null) {
      cc.setCrlControl(crlControl.getConfPairs().asMap());
    }

    // CTLog Control
    CtlogControl ctlogControl = caEntry.getCtlogControl();
    if (ctlogControl != null) {
      cc.setCtlogControl(ctlogControl.getConfPairs().asMap());
    }

    ConfPairs extraControl = caEntry.getExtraControl();
    if (extraControl != null) {
      cc.setExtraControl(extraControl.asMap());
    }

    RevokeSuspendedControl revokeSuspendedControl = caEntry.getRevokeSuspendedControl();
    if (revokeSuspendedControl != null) {
      cc.setRevokeSuspendedControl(revokeSuspendedControl.getConfPairs().asMap());
    }

    return cc;
  }

  public static CaConfColumn fromCaInfo(CaConfType.CaInfo caEntry) throws InvalidConfException {
    CaConfColumn cc = fromBaseCaInfo(caEntry);

    cc.setPermission(PermissionConstants.toIntPermission(caEntry.getPermissions()));

    // CRL Control
    if (caEntry.getCrlControl() != null) {
      cc.setCrlControl(new ConfPairs(caEntry.getCrlControl()).asMap());
    }

    // CTLog Control
    if (caEntry.getCtlogControl() != null) {
      cc.setCtlogControl(new ConfPairs(caEntry.getCtlogControl()).asMap());
    }

    if (caEntry.getExtraControl() != null) {
      cc.setExtraControl(caEntry.getExtraControl());
    }

    if (caEntry.getRevokeSuspendedControl() != null) {
      cc.setRevokeSuspendedControl(new ConfPairs(caEntry.getRevokeSuspendedControl()).asMap());
    }

    return cc;
  }

  private static CaConfColumn fromBaseCaInfo(BaseCaInfo caEntry) {
    CaConfColumn cc = new CaConfColumn();

    // CA URIS
    CaUris caUris = caEntry.getCaUris();
    if (caUris != null) {
      cc.setCacertUris(caUris.getCacertUris());
      cc.setCrlUris(caUris.getCrlUris());
      cc.setDeltaCrlUris(caUris.getDeltaCrlUris());
      cc.setOcspUris(caUris.getOcspUris());
    }

    cc.setKeypairGenNames(caEntry.getKeypairGenNames());
    cc.setMaxValidity(caEntry.getMaxValidity());
    cc.setNumCrls(caEntry.getNumCrls());
    cc.setSaveCert(caEntry.isSaveCert());
    cc.setSaveKeypair(caEntry.isSaveKeypair());
    cc.setSnSize(caEntry.getSnSize());
    cc.setValidityMode(caEntry.getValidityMode());
    cc.setExpirationPeriod(caEntry.getExpirationPeriod());
    cc.setKeepExpiredCertDays(caEntry.getKeepExpiredCertDays());

    return cc;
  }

  public String encode() {
    return CaJson.toPrettyJson(this);
  }

  public CaUris caUris() {
    return new CaUris(cacertUris, ocspUris, crlUris, deltaCrlUris);
  }

  public int snSize() {
    return (snSize > CaManager.MAX_SERIALNUMBER_SIZE)
      ? CaManager.MAX_SERIALNUMBER_SIZE
      : Math.max(snSize, CaManager.MIN_SERIALNUMBER_SIZE);
  }

  private RevokeSuspendedControl revokeSuspendedControl() {
     return revokeSuspendedControl == null
        ? new RevokeSuspendedControl(false)
        : new RevokeSuspendedControl(new ConfPairs(revokeSuspendedControl));
  }

  private Validity maxValidity() {
    return maxValidity;
  }

  private CrlControl crlControl() throws CaMgmtException {
    ConfPairs pairs = new ConfPairs(crlControl);
    try {
      return new CrlControl(pairs);
    } catch (InvalidConfException ex) {
      throw new CaMgmtException("invalid CRL_CONTROL: " + pairs, ex);
    }
  }

  private CtlogControl ctlogControl() throws CaMgmtException {
    if (ctlogControl == null) {
      return null;
    }

    ConfPairs pairs = new ConfPairs(ctlogControl);
    try {
      return new CtlogControl(pairs);
    } catch (InvalidConfException ex) {
      throw new CaMgmtException("invalid CTLOG_CONTROL: " + pairs.getEncoded(), ex);
    }
  }

  private ConfPairs extraControl() {
    return extraControl == null ? null : new ConfPairs(extraControl).unmodifiable();
  }

  private ValidityMode validityMode() {
    return validityMode == null ? ValidityMode.strict : validityMode;
  }

}
