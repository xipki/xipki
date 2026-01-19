// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.profile.ctrl.ValidityMode;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.misc.StringUtil;

import java.util.List;

/**
 * Management Entry Change CA.
 * @author Lijun Liao (xipki)
 *
 */

public class ChangeCaEntry extends MgmtEntry {

  private final NameId ident;

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

  private ValidityMode validityMode;

  private List<String> permissions;

  private Integer keepExpiredCertDays;

  private Integer expirationPeriod;

  private String extraControl;

  private CaUris caUris;

  private byte[] encodedCert;

  private List<byte[]> encodedCertchain;

  private Integer numCrls;

  private Integer serialNoLen;

  public ChangeCaEntry(NameId ident) {
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
    this.crlSignerName = (crlSignerName == null) ? null
        : crlSignerName.toLowerCase();
  }

  public List<String> getKeypairGenNames() {
    return keypairGenNames;
  }

  public void setKeypairGenNames(List<String> keypairGenNames) {
    this.keypairGenNames = (keypairGenNames == null) ? null
        : StringUtil.lowercase(keypairGenNames);
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

  public List<String> getPermissions() {
    return permissions;
  }

  public void setPermissions(List<String> permissions) {
    this.permissions = permissions;
  }

  public Integer getExpirationPeriod() {
    return expirationPeriod;
  }

  public void setExpirationPeriod(Integer expirationPeriod) {
    this.expirationPeriod = expirationPeriod;
  }

  public Integer getKeepExpiredCertDays() {
    return keepExpiredCertDays;
  }

  public void setKeepExpiredCertDays(Integer days) {
    this.keepExpiredCertDays = days;
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
      Args.range(serialNoLen, "serialNoLen", CaManager.MIN_SERIALNUMBER_SIZE,
          CaManager.MAX_SERIALNUMBER_SIZE);
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

  @Override
  public JsonMap toCodec() {
    JsonMap map = new JsonMap()
        .put("ident",         ident)
        .putEnum("status",    status)
        .put("signerType",    signerType)
        .put("signerConf",    signerConf)
        .put("crlControl",    crlControl)
        .put("ctlogControl",  ctlogControl)
        .put("revokeSuspendedControl", revokeSuspendedControl)
        .put("crlSignerName", crlSignerName)
        .putStrings("keypairGenNames", keypairGenNames)
        .put("saveCert",      saveCert)
        .put("saveKeypair",   saveKeypair)
        .putEnum("validityMode",  validityMode)
        .putStrings("permissions",     permissions)
        .put("keepExpiredCertDays",    keepExpiredCertDays)
        .put("expirationPeriod",       expirationPeriod)
        .put("extraControl", extraControl)
        .put("caUris",       caUris)
        .put("numCrls",      numCrls)
        .put("serialNoLen",  serialNoLen)
        .put("encodedCert",  encodedCert)
        .putBytesCol("encodedCertchain", encodedCertchain);

    if (maxValidity != null) {
      map.put("maxValidity",    maxValidity.toString());
    }
    return map;
  }

  public static ChangeCaEntry parse(JsonMap json) throws CodecException {
    ChangeCaEntry ret = new ChangeCaEntry(
        NameId.parse(json.getNnMap("ident")));

    ret.setSignerType(json.getString("signerType"));
    ret.setSignerConf(json.getString("signerConf"));
    ret.setCrlControl(json.getString("crlControl"));
    ret.setCtlogControl(json.getString("ctlogControl"));
    ret.setRevokeSuspendedControl(json.getString("revokeSuspendedControl"));
    ret.setCrlSignerName(json.getString("crlSignerName"));
    ret.setKeypairGenNames(json.getStringList("keypairGenNames"));
    ret.setSaveCert(json.getBool("saveCert"));
    ret.setSaveKeypair(json.getBool("saveKeypair"));
    ret.setPermissions(json.getStringList("permissions"));
    ret.setKeepExpiredCertDays(json.getInt("keepExpiredCertDays"));
    ret.setExpirationPeriod(json.getInt("expirationPeriod"));
    ret.setExtraControl(json.getString("extraControl"));
    ret.setEncodedCert(json.getBytes("encodedCert"));
    ret.setEncodedCertchain(json.getBytesList("encodedCertchain"));
    ret.setNumCrls(json.getInt("numCrls"));
    ret.setSerialNoLen(json.getInt("serialNoLen"));

    String str = json.getString("maxValidity");
    if (str != null) {
      ret.setMaxValidity(Validity.getInstance(str));
    }

    str = json.getString("status");
    if (str != null) {
      ret.setStatus(CaStatus.forName(str));
    }

    str = json.getString("validityMode");
    if (str != null) {
      ret.setValidityMode(ValidityMode.forName(str));
    }

    JsonMap map = json.getMap("caUris");
    if (map != null) {
      ret.setCaUris(CaUris.parse(map));
    }

    return ret;
  }

}
