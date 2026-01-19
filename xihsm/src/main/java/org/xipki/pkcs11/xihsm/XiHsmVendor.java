// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm;

import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import org.xipki.pkcs11.wrapper.type.CkVersion;
import org.xipki.pkcs11.wrapper.vendor.HsmVendor;
import org.xipki.pkcs11.wrapper.vendor.SpecialBehaviour;
import org.xipki.pkcs11.wrapper.vendor.VendorEnum;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author Lijun Liao (xipki)
 */
public class XiHsmVendor extends HsmVendor {

  public static final long CKM_CLOUDHSM_AES_KEY_WRAP_ZERO_PAD = 0x8000216FL;

  private final String manufactureID;

  private final String libraryDescription;

  private final CkVersion cryptokiVersion;

  private final CkVersion libraryVersion;

  private final Set<Long> includeKeyTypes = new HashSet<>();

  private final Map<Long, CkMechanismInfo> mechanisms;

  private final long[] ckms;

  private final boolean privateObjectVisibleToOther;

  protected XiHsmVendor(
      String name, String manufactureID, String libraryDescription,
      CkVersion cryptokiVersion, CkVersion libraryVersion,
      String vendorEnum, int maxFrameSize, boolean privateObjectVisibleToOther,
      JsonList jsonCkmMultipartExclude,
      List<SpecialBehaviour> specialBehaviours,
      JsonMap jsonNameToCodeMap, Map<String, String> mechanisms)
      throws Exception {
    super(name, vendorEnum, maxFrameSize, null, jsonCkmMultipartExclude,
        specialBehaviours, jsonNameToCodeMap);
    this.manufactureID = Args.notBlank(manufactureID, "manufactureID");
    this.libraryDescription = Args.notBlank(libraryDescription,
        "libraryDescription");
    this.cryptokiVersion = Args.notNull(cryptokiVersion, "cryptokiVersion");
    this.libraryVersion = Args.notNull(libraryVersion, "libraryVersion");
    this.privateObjectVisibleToOther = privateObjectVisibleToOther;

    Map<Long, CkMechanismInfo> mechanismInfoMap = new HashMap<>();
    for (Map.Entry<String, String> v : mechanisms.entrySet()) {
      long ckm = nameToCode2(Category.CKM, v.getKey());
      String[] tokens2 = v.getValue().split("/");
      int minKeySize = Integer.parseInt(tokens2[0]);
      int maxKeySize = Integer.parseInt(tokens2[1]);
      String[] flagTexts = tokens2[2].split(":");
      long flags = 0;
      for (String flagText : flagTexts) {
        Long flag = PKCS11T.nameToCode(
            Category.CKF_MECHANISM, "CKF_" + flagText);
        if (flag == null) {
          throw new Exception("unknown flag " + flagText);
        }
        flags |= flag;
      }

      CkMechanismInfo mechInfo =
          new CkMechanismInfo(minKeySize, maxKeySize, flags);
      mechanismInfoMap.put(ckm, mechInfo);
    }

    this.mechanisms = Collections.unmodifiableMap(mechanismInfoMap);
    List<Long> sortedCkms = new ArrayList<>(this.mechanisms.keySet());
    Collections.sort(sortedCkms);

    // mechanisms
    this.ckms = new long[sortedCkms.size()];
    int idx = 0;
    for (long ckm : sortedCkms) {
      this.ckms[idx++] = ckm;
    }
  }

  public void addIncludeKeyType(String keyType) {
    includeKeyTypes.add(nameToCode2(Category.CKK, keyType));
  }

  public String getManufactureID() {
    return manufactureID;
  }

  public String getLibraryDescription() {
    return libraryDescription;
  }

  public CkVersion getCryptokiVersion() {
    return cryptokiVersion;
  }

  public CkVersion getLibraryVersion() {
    return libraryVersion;
  }

  public boolean isPrivateObjectVisibleToOther() {
    return privateObjectVisibleToOther;
  }

  public boolean supportsCkk(long ckk) {
    return includeKeyTypes.contains(ckk);
  }

  public Map<Long, CkMechanismInfo> getMechanisms() {
    return mechanisms;
  }

  public void assertCryptokiVersionSupported(CkVersion version)
      throws HsmException {
    if (cryptokiVersion.version() < version.version()) {
      throw new HsmException(PKCS11T.CKR_FUNCTION_NOT_SUPPORTED,
          "unsupported version " + version);
    }
  }

  public void assertCkkSupported(long ckk) throws HsmException {
    if (!supportsCkk(ckk)) {
      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID,
          "Key type " + codeToName(Category.CKK, ckk) + " is not supported.");
    }
  }

  public long[] getCkms() {
    return ckms.clone();
  }

  public CkMechanismInfo getMechanismInfo(long ckm) {
    return mechanisms.get(ckm);
  }

  public void assertCkmSupported(long ckm, long flagBit) throws HsmException {
    CkMechanismInfo mi = mechanisms.get(ckm);
    if (mi != null) {
      if ((mi.flags() & flagBit) == flagBit) {
        return;
      }
    }

    throw new HsmException(PKCS11T.CKR_MECHANISM_INVALID,
        "mechanism " + PKCS11T.ckmCodeToName(ckm) +
        " for " + codeToName(Category.CKF_MECHANISM, flagBit) +
        " is not supported");
  }

  public void assertFrameSize(int size) throws HsmException {
    if (size <= maxFrameSize) {
      return;
    }

    long ckr = vendorEnum == VendorEnum.TASS
        ? PKCS11T.CKR_DEVICE_ERROR : PKCS11T.CKR_DATA_LEN_RANGE;
    throw new HsmException(ckr,
        "frame date too long (" + size + " > " + maxFrameSize + ")");
  }

  private long nameToCode2(Category category, String ckmStr) {
    Long genericCkmL = nameToCode(category, ckmStr);
    if (genericCkmL == null) {
      return parseCode(category, ckmStr);
    } else {
      return genericToVendorCode(category, genericCkmL);
    }
  }

  public static XiHsmVendor getInstance(String vendorName) throws Exception {
    String basedir = "org/xipki/pkcs11/xihsm/vendor/";
    String confPath = basedir + "list.json";
    List<String> vendorFileNames;
    try (InputStream in = XiHsmVendor.class.getClassLoader()
        .getResourceAsStream(confPath)) {
      if (in == null) {
        throw new IOException("found no file " + confPath);
      }
      vendorFileNames = JsonParser.parseList(in, true).toStringList();
    }

    JsonMap block = null;
    for (String vendorFileName : vendorFileNames) {
      String vendorFilePath = basedir + vendorFileName;
      try (InputStream in = XiHsmVendor.class.getClassLoader()
          .getResourceAsStream(vendorFilePath)) {
        if (in == null) {
          throw new IOException("found no file " + vendorFilePath);
        }
        JsonMap v = JsonParser.parseMap(in,true);
        String tname = v.getNnString("name");
        if (vendorName.equals(tname)) {
          block = v;
          break;
        }
      }
    }

    if (block == null) {
      throw new IOException("found no block " + vendorName);
    }

    String manufactureID = block.getNnString("manufacturerID");
    String libDescription = block.getNnString("libDescription");
    String cryptokiVersionText = block.getNnString("cryptokiVersion");
    String libVersionText = block.getNnString("libVersion");

    String[] versionTokens = cryptokiVersionText.split("\\.");
    CkVersion cryptokiVersion = new CkVersion(
        Byte.parseByte(versionTokens[0]), Byte.parseByte(versionTokens[1]));

    versionTokens = libVersionText.split("\\.");
    CkVersion libVersion = new CkVersion(
        Byte.parseByte(versionTokens[0]), Byte.parseByte(versionTokens[1]));

    JsonList jsonCkmMultipartExclude =
        block.getList("ckmMultipartExclude");

    List<SpecialBehaviour> behaviours =
        block.getEnumList("specialBehaviours", SpecialBehaviour.class);

    JsonMap jsonNameToCodeMap = block.getMap("nameToCodeMap");

    int maxFrameSize = Integer.MAX_VALUE;
    Integer i = block.getInt("maxFrameSize");
    if (i != null) {
      maxFrameSize = i;
    }

    Boolean b = block.getBool("privateObjectVisibleToOther");
    boolean privateObjectVisibleToOther = b != null && b;

    Map<String, String> mechanisms = block.getStringMap("mechanisms");
    // excludeObjectClasses
    XiHsmVendor ret = new XiHsmVendor(block.getNnString("name"),
        manufactureID, libDescription, cryptokiVersion, libVersion,
        block.getNnString("vendor"), maxFrameSize,
        privateObjectVisibleToOther,
        jsonCkmMultipartExclude, behaviours, jsonNameToCodeMap, mechanisms);

    // keyTypes
    List<String> list = block.getStringList("keyTypes");
    if (list != null) {
      for (String s : list) {
        ret.addIncludeKeyType(s);
      }
    }

    return ret;
  }

}
