// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.CtlogControl;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.RevokeSuspendedControl;
import org.xipki.ca.api.profile.ctrl.ValidityMode;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.type.Validity;

import java.util.List;

/**
 * Represent the CONF column in the table CA.
 *
 * @author Lijun Liao (xipki)
 */
public class CaConfColumn implements JsonEncodable {

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

  private Permissions permissions;

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

  public int version() {
    return version;
  }

  public void setVersion(int version) {
    this.version = version;
  }

  public int snSize() {
    return snSize;
  }

  public void setSnSize(int snSize) {
    this.snSize = snSize;
  }

  public List<String> cacertUris() {
    return cacertUris;
  }

  public void setCacertUris(List<String> cacertUris) {
    this.cacertUris = cacertUris;
  }

  public List<String> ocspUris() {
    return ocspUris;
  }

  public void setOcspUris(List<String> ocspUris) {
    this.ocspUris = ocspUris;
  }

  public List<String> crlUris() {
    return crlUris;
  }

  public void setCrlUris(List<String> crlUris) {
    this.crlUris = crlUris;
  }

  public List<String> deltaCrlUris() {
    return deltaCrlUris;
  }

  public void setDeltaCrlUris(List<String> deltaCrlUris) {
    this.deltaCrlUris = deltaCrlUris;
  }

  public Validity maxValidity() {
    return maxValidity;
  }

  public void setMaxValidity(Validity maxValidity) {
    this.maxValidity = maxValidity;
  }

  public List<String> keypairGenNames() {
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

  public ValidityMode validityMode() {
    return validityMode;
  }

  public void setValidityMode(ValidityMode validityMode) {
    this.validityMode = validityMode;
  }

  public Permissions permissions() {
    return permissions;
  }

  public void setPermissions(Permissions permissions) {
    this.permissions = permissions;
  }

  public int numCrls() {
    return numCrls;
  }

  public void setNumCrls(int numCrls) {
    this.numCrls = numCrls;
  }

  public int expirationPeriod() {
    return expirationPeriod;
  }

  public void setExpirationPeriod(int expirationPeriod) {
    this.expirationPeriod = expirationPeriod;
  }

  public int keepExpiredCertDays() {
    return keepExpiredCertDays;
  }

  public void setKeepExpiredCertDays(int keepExpiredCertDays) {
    this.keepExpiredCertDays = keepExpiredCertDays;
  }

  public CrlControl crlControl() {
    return crlControl;
  }

  public void setCrlControl(CrlControl crlControl) {
    this.crlControl = crlControl;
  }

  public CtlogControl ctlogControl() {
    return ctlogControl;
  }

  public void setCtlogControl(CtlogControl ctlogControl) {
    this.ctlogControl = ctlogControl;
  }

  public RevokeSuspendedControl revokeSuspendedControl() {
    return revokeSuspendedControl;
  }

  public void setRevokeSuspendedControl(
      RevokeSuspendedControl revokeSuspendedControl) {
    this.revokeSuspendedControl = revokeSuspendedControl;
  }

  public ConfPairs extraControl() {
    return extraControl;
  }

  public void setExtraControl(ConfPairs extraControl) {
    this.extraControl = extraControl;
  }

  public CaConfColumn copy() {
    try {
      return decode(encode());
    } catch (InvalidConfException e) {
      throw new RuntimeException("shall not happen", e);
    }
  }

  public static CaConfColumn decode(String encoded)
      throws InvalidConfException {
    try {
      return parse(JsonParser.parseMap(encoded, false));
    } catch (CodecException e) {
      throw new InvalidConfException (
          "error decoding CaConfColumn: " + e.getMessage(), e);
    }
  }

  public static CaConfColumn parse(JsonMap json)
      throws CodecException, InvalidConfException {
    CaConfColumn ret = new CaConfColumn();
    Integer i = json.getInt("version");
    if (i != null) {
      ret.setVersion(i);
    }

    i = json.getInt("snSize");
    if (i != null) {
      ret.setSnSize(i);
    }

    ret.setCacertUris(json.getStringList("cacertUris"));
    ret.setOcspUris  (json.getStringList("ocspUris"));
    ret.setCrlUris   (json.getStringList("crlUris"));
    ret.setDeltaCrlUris(json.getStringList("deltaCrlUris"));
    ret.setMaxValidity(Validity.getInstance(json.getNnString("maxValidity")));
    ConfPairs confPairs = ConfPairs.parse(json.getMap("crlControl"));
    if (confPairs != null) {
      ret.setCrlControl(new CrlControl(confPairs));
    }

    confPairs = ConfPairs.parse(json.getMap("ctlogControl"));
    if (confPairs != null) {
      ret.setCtlogControl(new CtlogControl(confPairs));
    }

    confPairs = ConfPairs.parse(json.getMap("revokeSuspendedControl"));
    if (confPairs != null) {
      ret.setRevokeSuspendedControl(new RevokeSuspendedControl(confPairs));
    }

    ret.setKeypairGenNames(json.getStringList("keypairGenNames"));

    Boolean b = json.getBool("saveCert");
    if (b != null) {
      ret.setSaveCert(b);
    }

    b = json.getBool("saveKeypair");
    if (b != null) {
      ret.setSaveKeypair(b);
    }

    String str = json.getString("validityMode");
    if (str != null) {
      ret.setValidityMode(ValidityMode.forName(str));
    }

    Object o = json.getObject("permissions");
    if (o == null) {
      o = json.getObject("permission");
    }

    if (o == null) {
      throw new CodecException("permissions is not present");
    }

    ret.setPermissions(Permissions.parseJson(o));

    i = json.getInt("numCrls");
    if (i != null) {
      ret.setNumCrls(i);
    }

    i = json.getInt("expirationPeriod");
    if (i != null) {
      ret.setExpirationPeriod(i);
    }

    i = json.getInt("keepExpiredCertDays");
    if (i != null) {
      ret.setKeepExpiredCertDays(i);
    }

    ret.setExtraControl(ConfPairs.parse(json.getMap("extraControl")));

    return ret;
  }

  public void fillBaseCaInfo(BaseCaInfo baseCaInfo) {
    baseCaInfo.setCaUris(caUris());
    baseCaInfo.setExpirationPeriod(expirationPeriod);
    baseCaInfo.setKeepExpiredCertDays(keepExpiredCertDays);
    baseCaInfo.setKeypairGenNames(keypairGenNames);
    baseCaInfo.setNumCrls(numCrls);
    baseCaInfo.setSaveCert(saveCert);
    baseCaInfo.setSnSize(snSize);
    baseCaInfo.setSaveKeypair(saveKeypair);
    baseCaInfo.setValidityMode(validityMode == null
        ? ValidityMode.STRICT : validityMode);
    baseCaInfo.setCrlControl(crlControl);
    baseCaInfo.setCtlogControl(ctlogControl);
    baseCaInfo.setExtraControl(extraControl);
    baseCaInfo.setRevokeSuspendedControl(revokeSuspendedControl);
  }

  public static CaConfColumn fromBaseCaInfo(BaseCaInfo baseCaInfo) {
    CaConfColumn cc = new CaConfColumn();

    // CA URIS
    CaUris caUris = baseCaInfo.caUris();
    if (caUris != null) {
      cc.setCacertUris(caUris.cacertUris());
      cc.setCrlUris(caUris.crlUris());
      cc.setDeltaCrlUris(caUris.deltaCrlUris());
      cc.setOcspUris(caUris.ocspUris());
    }

    cc.setKeypairGenNames(baseCaInfo.keypairGenNames());
    cc.setMaxValidity(baseCaInfo.maxValidity());
    cc.setNumCrls(baseCaInfo.numCrls());
    cc.setSaveCert(baseCaInfo.isSaveCert());
    cc.setSaveKeypair(baseCaInfo.isSaveKeypair());
    cc.setSnSize(baseCaInfo.snSize());
    cc.setValidityMode(baseCaInfo.validityMode());
    cc.setExpirationPeriod(baseCaInfo.expirationPeriod());
    cc.setKeepExpiredCertDays(baseCaInfo.keepExpiredCertDays());

    cc.setPermissions(baseCaInfo.permissions());
    cc.setCtlogControl(baseCaInfo.ctlogControl());
    cc.setCrlControl(baseCaInfo.crlControl());
    cc.setRevokeSuspendedControl(baseCaInfo.revokeSuspendedControl());
    cc.setExtraControl(baseCaInfo.extraControl());

    return cc;
  }

  public String encode() {
    return JsonBuilder.toPrettyJson(toCodec());
  }

  @Override
  public JsonMap toCodec() {
    JsonMap map = new JsonMap()
        .put("version",             version)
        .put("snSize",              snSize)
        .putStrings("cacertUris",   cacertUris)
        .putStrings("ocspUris",     ocspUris)
        .putStrings("crlUris",      crlUris)
        .putStrings("deltaCrlUris", deltaCrlUris)
        .putStrings("keypairGenNames", keypairGenNames)
        .put("saveCert",            saveCert)
        .put("saveKeypair",         saveKeypair)
        .putEnum("validityMode",        validityMode)
        .put("numCrls",             numCrls)
        .put("expirationPeriod",    expirationPeriod)
        .put("keepExpiredCertDays", keepExpiredCertDays)
        .put("extraControl",        extraControl)
        .put("crlControl",          crlControl)
        .put("ctlogControl",        ctlogControl)
        .put("revokeSuspendedControl", revokeSuspendedControl)
        .put("permissions",         permissions.value());

    if (maxValidity != null) {
      map.put("maxValidity", maxValidity.toString());
    }
    return map;
  }

  public CaUris caUris() {
    return new CaUris(cacertUris, ocspUris, crlUris, deltaCrlUris);
  }

}
