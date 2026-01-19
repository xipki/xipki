// Copyright (c) 2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.wrapper.vendor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.type.CkInfo;
import org.xipki.pkcs11.wrapper.type.CkVersion;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_DECRYPT;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_DIGEST;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_ENCRYPT;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_SIGN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_VERIFY;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_VENDOR_DEFINED;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class HsmVendor {

  private static final Logger LOG = LoggerFactory.getLogger(HsmVendor.class);

  protected final String name;

  protected final VendorEnum vendorEnum;

  private final Map<Category, VendorMap> vendorMaps = new HashMap<>();

  private final Set<SpecialBehaviour> specialBehaviours = new HashSet<>();

  private final Map<Long, Long> ckmExclude = new HashMap<>();

  private final Map<Long, Long> ckmMultipartExclude = new HashMap<>();

  protected final int maxFrameSize;

  private static final long CKM_ALL = -1L;

  private HsmVendor() {
    this.name = null;
    this.vendorEnum = VendorEnum.UNKNOWN;
    this.maxFrameSize = Integer.MAX_VALUE;
  }

  protected HsmVendor(String vendorName,
                      String vendorEnum,
                      int maxFrameSize,
                      JsonList jsonCkmExclude,
                      JsonList jsonCkmMultipartExclude,
                      List<SpecialBehaviour> specialBehaviours,
                      JsonMap jsonNameToCodeMap)
      throws Exception {
    this.name = Args.notBlank(vendorName, "vendorName");
    this.vendorEnum = (vendorEnum == null) ? VendorEnum.UNKNOWN
        : VendorEnum.valueOf(vendorEnum);
    this.maxFrameSize = Args.range(
        maxFrameSize, "maxFrameSize", 1024, Integer.MAX_VALUE);

    // CKM exclude
    if (jsonCkmExclude != null) {
      interpretCkm(jsonCkmExclude.toMapList(), ckmExclude);
    }

    // CKM multipart exclude
    if (jsonCkmMultipartExclude != null) {
      interpretCkm(jsonCkmMultipartExclude.toMapList(), ckmMultipartExclude);
    }

    // special behaviours
    if (specialBehaviours != null) {
      this.specialBehaviours.addAll(specialBehaviours);
    }

    Category[] categories = {Category.CKD, Category.CKG_MGF,
        Category.CKK, Category.CKM, Category.CKP_PRF, Category.CKR,
        Category.CKU, Category.CKA};
    for (Category category : categories) {
      vendorMaps.put(category, new VendorMap(category));
    }

    if (jsonNameToCodeMap != null) {
      for (Map.Entry<String, String> entry
          : jsonNameToCodeMap.toStringMap().entrySet()) {
        String key = entry.getKey();
        Category category =
            key.startsWith("CKD_") ? Category.CKD
                : key.startsWith("CKG_") ? Category.CKG_MGF
                : key.startsWith("CKK_") ? Category.CKK
                : key.startsWith("CKM_") ? Category.CKM
                : key.startsWith("CKP_") ? Category.CKP_PRF
                : key.startsWith("CKR_") ? Category.CKR
                : key.startsWith("CKU_") ? Category.CKU
                : key.startsWith("CKA_") ? Category.CKA
                : null;

        if (category == null) {
          throw new Exception("Unknown name in vendor block: " + key);
        }

        vendorMaps.get(category).addNameCode(key,
            entry.getValue().toUpperCase(Locale.ROOT));
      }
    }
  }

  public static HsmVendor getInstance(
      String modulePath, CkInfo moduleInfo, Set<Long> tokenMechanisms)
      throws Exception {
    String basedir = "org/xipki/pkcs11/wrapper/vendor/";
    String confPath = basedir + "list.json";
    List<String> vendorFileNames;
    try (InputStream in = HsmVendor.class.getClassLoader()
        .getResourceAsStream(confPath)) {
      if (in == null) {
        throw new IOException("found no file " + confPath);
      }
      vendorFileNames = JsonParser.parseList(in, true).toStringList();
    }

    JsonMap block = null;
    JsonMap baseBlock = null;

    for (String vendorFileName : vendorFileNames) {
      String vendorFilePath = basedir + vendorFileName;
      try (InputStream in = HsmVendor.class.getClassLoader()
          .getResourceAsStream(vendorFilePath)) {
        JsonMap v = JsonParser.parseMap(in, true);
        JsonMap filter = v.getNnMap("filter");
        String baseFileName = v.getString("base");
        JsonMap baseFilter = null;

        if (baseFileName != null) {
          try (InputStream baseIn = HsmVendor.class.getClassLoader()
              .getResourceAsStream(basedir + baseFileName)) {
            baseBlock = JsonParser.parseMap(baseIn, true);
            baseFilter = v.getNnMap("filter");
            if (baseFilter.getString("base") != null) {
              throw new IOException(
                  "base vendor block shall not have filter.base field");
            }
          }
        }

        if (matches(filter, baseFilter, modulePath, moduleInfo,
            tokenMechanisms)) {
          block = v;
          break;
        }
      }
    }

    if (block == null) {
      return new HsmVendor();
    }

    LOG.info("found <vendor> configuration: {}", block);

    // CKM exclude
    String fieldName = "ckmExclude";
    JsonList jsonCkmExclude = block.getList(fieldName);
    if (baseBlock != null && jsonCkmExclude == null) {
      jsonCkmExclude = baseBlock.getList(fieldName);
    }

    // CKM multipart exclude
    fieldName = "ckmMultipartExclude";
    JsonList jsonCkmMultipartExclude = block.getList(fieldName);
    if (baseBlock != null && jsonCkmMultipartExclude == null) {
      jsonCkmMultipartExclude = baseBlock.getList(fieldName);
    }

    // vendor
    fieldName = "vendor";
    String vendorEnum = block.getString(fieldName);
    if (baseBlock != null && vendorEnum == null) {
      vendorEnum = baseBlock.getString(fieldName);
    }

    // special behaviours
    fieldName = "specialBehaviours";
    List<SpecialBehaviour> behaviours = block.getEnumList(
        fieldName, SpecialBehaviour.class);
    if (baseBlock != null && behaviours == null) {
      behaviours = baseBlock.getEnumList(
          fieldName, SpecialBehaviour.class);
    }

    fieldName = "nameToCodeMap";
    JsonMap jsonNameToCodeMap = block.getMap(fieldName);
    if (baseBlock != null && jsonNameToCodeMap == null) {
      jsonNameToCodeMap = baseBlock.getMap(fieldName);
    }

    // maxFrameSize;
    int maxFrameSize = Integer.MAX_VALUE;
    Integer i  = block.getInt("maxFrameSize");
    if (baseBlock != null && i == null) {
      i  = baseBlock.getInt("maxFrameSize");
    }

    if (i != null) {
      maxFrameSize = i;
    }

    return new HsmVendor(block.getNnString("name"), vendorEnum,
        maxFrameSize, jsonCkmExclude, jsonCkmMultipartExclude, behaviours,
        jsonNameToCodeMap);
  }

  public int getMaxFrameSize() {
    return maxFrameSize;
  }

  public String getName() {
    return name;
  }

  public VendorEnum getVendorEnum() {
    return vendorEnum;
  }

  public long adaptMechanismFlags(long ckm, long flags) {
    Long flagMask = ckmExclude.get(ckm);
    if (flagMask == null) {
      flagMask = ckmExclude.get(CKM_ALL);
    }

    if (flagMask == null) {
      return flags;
    }

    return flags & (~flagMask);
  }

  public boolean supportsMultipart(long ckm, long flagBit) {
    Long mapFlag = ckmMultipartExclude.get(ckm);
    if (mapFlag == null) {
      mapFlag = ckmMultipartExclude.get(CKM_ALL);
    }

    if (mapFlag == null) {
      return true;
    }

    return (mapFlag & flagBit) == 0;
  }

  public boolean hasSpecialBehaviour(SpecialBehaviour vendorBehavior) {
    return specialBehaviours.contains(vendorBehavior);
  }

  public boolean hasAnySpecialBehaviour(SpecialBehaviour... vendorBehaviors) {
    if (vendorBehaviors == null) {
      return false;
    }

    for (SpecialBehaviour v : vendorBehaviors) {
      if (specialBehaviours.contains(v)) {
        return true;
      }
    }

    return false;
  }

  public boolean hasAllSpecialBehaviours(SpecialBehaviour... vendorBehaviors) {
    if (vendorBehaviors == null) {
      return false;
    }

    for (SpecialBehaviour v : vendorBehaviors) {
      if (!specialBehaviours.contains(v)) {
        return false;
      }
    }

    return true;
  }

  public long genericToVendorCode(Category category, long genericCode) {
    VendorMap map = vendorMaps.get(category);
    return map != null ? map.genericToVendor(genericCode) : genericCode;
  }

  public long vendorToGenericCode(Category category, long vendorCode) {
    VendorMap map = vendorMaps.get(category);
    return map != null ? map.vendorToGeneric(vendorCode) : vendorCode;
  }

  public String codeToName(Category category, long code) {
    if ((code & CKM_VENDOR_DEFINED) != 0 && vendorMaps != null) {
      VendorMap map = vendorMaps.get(category);
      return map != null ? map.codeToName(code)
          : PKCS11T.codeToName(category, code);
    } else {
      return PKCS11T.codeToName(category, code);
    }
  }

  public Long nameToCode(Category category, String name) {
    VendorMap map = vendorMaps.get(category);
    return map != null ? map.nameToCode(name)
        : PKCS11T.nameToCode(category, name);
  }

  protected static void interpretCkm(
      List<JsonMap> list, Map<Long, Long> map)
      throws CodecException {
    for (JsonMap m : list) {
      String ckm = m.getNnString("ckm");
      List<String> flagTexts = m.getNnStringList("flags");

      long flags = 0;
      if (flagTexts.size() == 1 && flagTexts.get(0).equals("*")) {
        flags = CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT | CKF_DIGEST;
      } else {
        for (String f : flagTexts) {
          String c14nFlag = f.toUpperCase(Locale.ROOT)
              .replace("-", "")
              .replace("_", "");

          switch (c14nFlag) {
            case "SIGN":
              flags |= CKF_SIGN;
              break;
            case "VERIFY":
              flags |= CKF_VERIFY;
              break;
            case "ENCRYPT":
              flags |= CKF_ENCRYPT;
              break;
            case "DECRYPT":
              flags |= CKF_DECRYPT;
              break;
            case "DIGEST":
              flags |= CKF_DIGEST;
              break;
            default:
              LOG.warn("unknown function {}", f);
          }
        }
      }

      Long code;
      if ("*".contentEquals(ckm)) {
        code = CKM_ALL;
      } else if (ckm.startsWith("0X")) {
        try {
          code = Long.parseLong(ckm.substring(2), 16);
        } catch (NumberFormatException e) {
          code = null;
        }
      } else {
        code = PKCS11T.ckmNameToCode(ckm);
      }

      if (code == null) {
        LOG.warn("unknown CKM in {}", ckm);
        continue;
      }

      map.put(code, flags);
    }
  }

  public static long parseCode(Category category, String str) {
    if (str == null || str.isEmpty()) {
      throw new IllegalArgumentException("invalid code '" + str + "'");
    }
    char c = str.charAt(0);
    if (c >= '0' && c <= '9') {
      return parseCode(str);
    } else {
      Long l = PKCS11T.nameToCode(category, str);
      if (l == null) {
        throw new IllegalArgumentException("invalid code '" + str + "'");
      }
      return l;
    }
  }

  private static long parseCode(String str) {
    boolean hex = str.startsWith("0X") || str.startsWith("0x");
    return hex ? Long.parseLong(str.substring(2), 16) : Long.parseLong(str);
  }

  private static boolean matches(
      JsonMap filter, JsonMap baseFilter,
      String modulePath, CkInfo moduleInfo, Set<Long> tokenMechanisms)
      throws CodecException {
    String fieldName = "modulePaths";
    List<String> modulePaths = filter.getStringList(fieldName);
    if (baseFilter != null && modulePaths == null) {
      modulePaths = filter.getStringList(fieldName);
    }

    fieldName = "manufacturerIDs";
    List<String> manufacturerIDs = filter.getStringList(fieldName);
    if (baseFilter != null && manufacturerIDs == null) {
      manufacturerIDs = filter.getStringList(fieldName);
    }

    fieldName = "descriptions";
    List<String> descriptions = filter.getStringList(fieldName);
    if (baseFilter != null && descriptions == null) {
      descriptions = filter.getStringList(fieldName);
    }

    fieldName = "versions";
    List<String> versions = filter.getStringList(fieldName);
    if (baseFilter != null && versions == null) {
      versions = filter.getStringList(fieldName);
    }

    fieldName = "mechanisms";
    JsonMap jsonMechanism = filter.getMap(fieldName);
    if (baseFilter != null && jsonMechanism == null) {
      jsonMechanism = filter.getMap(fieldName);
    }

    String mid = moduleInfo.manufacturerID();
    String desc = moduleInfo.libraryDescription();
    String moduleFileName = Paths.get(modulePath).getFileName().toString();
    if ((isNotEmpty(modulePaths) && notContains(modulePaths, moduleFileName)) ||
        (isNotEmpty(manufacturerIDs) && notContains(manufacturerIDs, mid)) ||
        (isNotEmpty(descriptions) && notContains(descriptions, desc))) {
      return false;
    }

    if (isNotEmpty(versions)) {
      CkVersion libVersion = moduleInfo.libraryVersion();
      int iVersion = ((0xFF & libVersion.major()) << 8)
                      + (0xFF & libVersion.minor());
      boolean match = false;
      for (String t : versions) {
        int idx = t.indexOf("-");
        int from = (idx == -1) ? toIntVersion(t)
            : toIntVersion(t.substring(0, idx));
        int to = (idx == -1) ? from : toIntVersion(t.substring(idx + 1));

        if (iVersion >= from && iVersion <= to) {
          match = true;
          break;
        }
      }

      if (!match) {
        return false;
      }
    }

    boolean match = true;
    if ((tokenMechanisms != null && jsonMechanism != null)) {
      List<String> mechanismTexts = jsonMechanism.getStringList("with");
      if (mechanismTexts != null && !mechanismTexts.isEmpty()) {
        for (String m : mechanismTexts) {
          long code = parseCode(Category.CKM, m);
          if (!tokenMechanisms.contains(code)) {
            match = false;
            break;
          }
        }
      }

      if (match) {
        mechanismTexts = jsonMechanism.getStringList("without");
        if (mechanismTexts != null && !mechanismTexts.isEmpty()) {
          for (String m : mechanismTexts) {
            long code = parseCode(Category.CKM, m);
            if (tokenMechanisms.contains(code)) {
              match = false;
              break;
            }
          }
        }
      }
    }

    return match;
  }

  private static int toIntVersion(String version) {
    StringTokenizer st = new StringTokenizer(version, ".");
    return (Integer.parseInt(st.nextToken()) << 8)
        + Integer.parseInt(st.nextToken());
  }

  private static boolean isNotEmpty(Collection<?> c) {
    return c != null && !c.isEmpty();
  }

  private static boolean notContains(List<String> list, String str) {
    str = str.toLowerCase(Locale.ROOT);
    for (String s : list) {
      if (str.contains(s)) {
        return false;
      }
    }
    return true;
  }

  private static final class VendorMap {

    private final Map<Long, Long> genericToVendorMap = new HashMap<>();

    private final Map<Long, Long> vendorToGenericMap = new HashMap<>();

    private final Map<Long, String> codeNameMap = new HashMap<>();

    private final Map<String, Long> nameCodeMap = new HashMap<>();

    private final Category category;

    private VendorMap(Category category) {
      this.category = category;
    }

    private void addNameCode(String name, String code) {
      long lCode = parseCode(code);
      Long genericCode = PKCS11T.nameToCode(category, name);
      if (genericCode != null) {
        // the given name is already defined in the generic constants.
        if ((genericCode & PKCS11T.CKM_VENDOR_DEFINED) != 0
            && genericCode != lCode) {
          // only vendor code is allowed to be overwritten.
          genericToVendorMap.put(genericCode, lCode);
          vendorToGenericMap.put(lCode, genericCode);
        }
      } else {
        codeNameMap.put(lCode, name);
        nameCodeMap.put(name, lCode);
      }
    }

    long genericToVendor(long genericCode) {
      return genericToVendorMap.getOrDefault(genericCode, genericCode);
    }

    long vendorToGeneric(long vendorCode) {
      return vendorToGenericMap.getOrDefault(vendorCode, vendorCode);
    }

    public String codeToName(long code) {
      String name = codeNameMap.get(code);
      if (name == null) {
        name = PKCS11T.codeToName(category, code);
      }
      return name;
    }

    public Long nameToCode(String name) {
      Long code = nameCodeMap.get(name);
      if (code == null) {
        code = PKCS11T.nameToCode(category, name);
      }
      return code;
    }

  }

}
