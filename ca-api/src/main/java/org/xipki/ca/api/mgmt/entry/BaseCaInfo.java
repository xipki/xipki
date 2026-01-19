// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.CtlogControl;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.RevokeSuspendedControl;
import org.xipki.ca.api.profile.ctrl.ValidityMode;
import org.xipki.security.CertRevocationInfo;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.misc.CompareUtil;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.misc.StringUtil;

import java.util.List;

/**
 * This class fields of a single CA, which are common of different real CA
 * classes.
 *
 * @author Lijun Liao (xipki)
 */
public class BaseCaInfo {

  private final String signerType;

  private CaUris caUris;

  private CrlControl crlControl;

  private String crlSignerName;

  private CtlogControl ctlogControl;

  private int expirationPeriod = 365; // days

  private ConfPairs extraControl;

  private int keepExpiredCertDays = -1; // keep forever

  private List<String> keypairGenNames;

  private Validity maxValidity;

  private long nextCrlNo;

  private int numCrls = 30;

  private final Permissions permissions;

  private CertRevocationInfo revocationInfo;

  private RevokeSuspendedControl revokeSuspendedControl;

  private boolean saveCert = true;

  private boolean saveKeypair = false;

  private int snSize = 20;

  private CaStatus status = CaStatus.active;

  /**
   * Valid values are strict, cutoff and by_ca. Default is strict
   */
  private ValidityMode validityMode = ValidityMode.STRICT;

  public BaseCaInfo(String signerType, Permissions permissions) {
    this.signerType  = Args.notBlank(signerType, "signerType");
    this.permissions = Args.notNull(permissions, "permissions");
  }

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

  public void setMaxValidity(Validity maxValidity) {
    this.maxValidity = maxValidity;
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
    this.status = Args.notNull(status, "status");
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

  public final void setRevokeSuspendedControl(
      RevokeSuspendedControl revokeSuspendedControl) {
    this.revokeSuspendedControl = revokeSuspendedControl;
  }

  public final ConfPairs getExtraControl() {
    return extraControl;
  }

  public final void setExtraControl(ConfPairs extraControl) {
    this.extraControl = extraControl;
  }

  protected boolean equals(BaseCaInfo obj, boolean ignoreDynamicFields) {
    if (!ignoreDynamicFields) {
      if (nextCrlNo != obj.nextCrlNo) {
        return false;
      }
    }

    return CompareUtil.equals(caUris, obj.caUris)
        && CompareUtil.equals(crlSignerName, obj.crlSignerName)
        && (expirationPeriod == obj.expirationPeriod)
        && (keepExpiredCertDays == obj.keepExpiredCertDays)
        && CompareUtil.equals(keypairGenNames, obj.keypairGenNames)
        && CompareUtil.equals(maxValidity, obj.maxValidity)
        && (numCrls == obj.numCrls)
        && CompareUtil.equals(revocationInfo, obj.revocationInfo)
        && (saveCert == obj.saveCert)
        && (saveKeypair == obj.saveKeypair)
        && signerType.equals(obj.signerType)
        && (snSize == obj.snSize)
        && CompareUtil.equals(status, obj.status)
        && CompareUtil.equals(validityMode, obj.validityMode)
        && CompareUtil.equals(permissions,  obj.permissions)
        && CompareUtil.equals(crlControl,   obj.crlControl)
        && CompareUtil.equals(ctlogControl, obj.ctlogControl)
        && CompareUtil.equals(extraControl, obj.extraControl)
        && CompareUtil.equals(revokeSuspendedControl,
            obj.revokeSuspendedControl);
  }

  protected String toString(boolean verbose) {
    String extraCtrlText;
    if (extraControl == null) {
      extraCtrlText = "-";
    } else {
      extraCtrlText = extraControl.getEncoded();
      if (!verbose && extraCtrlText.length() > 100) {
        extraCtrlText = StringUtil.concat(extraCtrlText.substring(0, 97),
            "...");
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
        "\nCRL signer name:      ",
            (crlSignerName == null ? "-" : crlSignerName),
        "\nsave certificate:     ", saveCert,
        "\nsave keypair:         ", saveKeypair,
        "\nvalidity mode:        ", validityMode,
        "\npermissions:          ", permissions,
        "\nkeep expired certs:   ", (keepExpiredCertDays < 0 ? "forever"
                                    : keepExpiredCertDays + " days"),
        "\nextra control:        ", extraCtrlText,
        "\nserial number length: ", snSize, " bytes",
        "\nrevocation:           ",
            (revocationInfo == null ? "not revoked" : "revoked"), revInfoText,
        "\nnext CRL number:      ", nextCrlNo,
        "\nKeyPair generators:   ",
            (keypairGenNames == null ? "-" : keypairGenNames),
        "\n", getCaUris(),
        "\nCRL control:\n", (crlControl == null ? "  -"
            : crlControl.toString(verbose)),
        "\nCTLog control:\n", (ctlogControl == null ? "  -"
            : ctlogControl.toString(verbose)),
        "\nrevoke suspended certificates control: \n",
            (revokeSuspendedControl == null ? "  -"
                : revokeSuspendedControl.toString(verbose)));
  }

  public void toJson(JsonMap map) {
    map.put("caUris",               caUris)
        .put("crlSignerName",       crlSignerName)
        .put("expirationPeriod",    expirationPeriod)
        .put("keepExpiredCertDays", keepExpiredCertDays)
        .putStrings("keypairGenNames", keypairGenNames)
        .put("nextCrlNo",      nextCrlNo)
        .put("numCrls",        numCrls)
        .put("revocationInfo", revocationInfo)
        .put("saveCert",       saveCert)
        .put("saveKeypair",    saveKeypair)
        .put("signerType",     signerType)
        .put("snSize",         snSize)
        .putEnum("status",         status)
        .put("extraControl",   extraControl)
        .putEnum("validityMode",   validityMode)
        .putStrings("permissions", permissions.toPermissionTexts())
        .put("crlControl",     crlControl)
        .put("ctlogControl",   ctlogControl)
        .put("revokeSuspendedControl", revokeSuspendedControl);

    if (maxValidity != null) {
      map.put("maxValidity",    maxValidity.toString());
    }
  }

  public static BaseCaInfo parse(JsonMap json)
      throws CodecException {
    BaseCaInfo ret = new BaseCaInfo(json.getNnString("signerType"),
        Permissions.parseJson(json.getObject("permissions")));

    JsonMap map = json.getMap("caUris");
    if (map != null) {
      ret.setCaUris(CaUris.parse(map));
    }

    ret.setCrlSignerName(json.getString("crlSignerName"));

    Integer i = json.getInt("expirationPeriod");
    if (i != null) {
      ret.setExpirationPeriod(i);
    }

    i = json.getInt("keepExpiredCertDays");
    if (i != null) {
      ret.setKeepExpiredCertDays(i);
    }

    ret.setKeypairGenNames(json.getStringList("keypairGenNames"));

    ret.setMaxValidity(
        Validity.getInstance(json.getNnString("maxValidity")));

    Long l = json.getLong("nextCrlNo");
    if (l != null) {
      ret.setNextCrlNo(l);
    }

    i = json.getInt("numCrls");
    if (i != null) {
      ret.setNumCrls(i);
    }

    String str = json.getString("revocationInfo");
    if (str != null) {
      ret.setRevocationInfo(CertRevocationInfo.fromEncoded(str));
    }

    Boolean b = json.getBool("saveCert");
    if (b != null) {
      ret.setSaveCert(b);
    }

    b = json.getBool("saveKeypair");
    if (b != null) {
      ret.setSaveKeypair(b);
    }

    i = json.getInt("snSize");
    if (i != null) {
      ret.setSnSize(i);
    }

    str = json.getString("status");
    if (str != null) {
      ret.setStatus(CaStatus.valueOf(str));
    }

    ConfPairs confPairs = ConfPairs.parse(json.getMap("crlControl"));
    try {
      if (confPairs != null) {
        ret.setCrlControl(new CrlControl(confPairs));
      }

      confPairs = ConfPairs.parse(json.getMap("ctlogControl"));
      if (confPairs != null) {
        ret.setCtlogControl(new CtlogControl(confPairs));
      }
    } catch (InvalidConfException e) {
      throw new CodecException(e);
    }

    confPairs = ConfPairs.parse(json.getMap("revokeSuspendedControl"));
    if (confPairs != null) {
      ret.setRevokeSuspendedControl(new RevokeSuspendedControl(confPairs));
    }

    confPairs = ConfPairs.parse(json.getMap("extraControl"));
    if (confPairs != null) {
      ret.setExtraControl(confPairs);
    }

    str = json.getString("validityMode");
    if (str != null) {
      ret.setValidityMode(ValidityMode.forName(str));
    }

    return ret;
  }

}
