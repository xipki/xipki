// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.extn;

import org.xipki.ca.certprofile.xijson.conf.extn.SingleKeyUsages;
import org.xipki.ca.certprofile.xijsonv1.conf.V1XijsonCertprofileType;
import org.xipki.security.KeySpec;
import org.xipki.security.KeyUsage;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CompareUtil;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Extension KeyUsage.
 *
 * @author Lijun Liao (xipki)
 */

public class V1KeyUsages {

  private final List<Usage> usages;

  private V1KeyUsages(List<Usage> usages) {
    this.usages = Collections.unmodifiableList(
        Args.notEmpty(usages, "usages"));
  }

  public List<Usage> getUsages() {
    return usages;
  }

  private org.xipki.ca.certprofile.xijson.conf.extn.KeyUsage toSingleV2() {
    Set<KeyUsage> rList = new HashSet<>(usages.size());
    Set<KeyUsage> oList = new HashSet<>(usages.size());

    for (Usage u : usages) {
      KeyUsage ku = KeyUsage.getKeyUsage(u.value);
      (u.required ? rList : oList).add(ku);
    }

    List<KeyUsage> sortedRList = rList.isEmpty() ? null : toSortedUsages(rList);

    List<KeyUsage> sortedOList = oList.isEmpty() ? null : toSortedUsages(oList);

    SingleKeyUsages singleKeyUsages = new SingleKeyUsages(
        null, sortedRList, sortedOList);

    return new org.xipki.ca.certprofile.xijson.conf.extn.KeyUsage(
        List.of(singleKeyUsages));
  }

  public org.xipki.ca.certprofile.xijson.conf.extn.KeyUsage toV2(
      Collection<KeySpec> keySpecs) {
    Set<KeySpec> signOnlyKeys    = new HashSet<>();
    Set<KeySpec> encryptOnlyKeys = new HashSet<>();
    Set<KeySpec> bothKeys        = new HashSet<>();

    if (keySpecs == null) {
      keySpecs = new HashSet<>(List.of(KeySpec.values()));
    }

    for (KeySpec keySpec : keySpecs) {
      if (keySpec.isEdwardsEC() || keySpec.isMldsa()) {
        signOnlyKeys.add(keySpec);
      } else if (keySpec.isMontgomeryEC() || keySpec.isMlkem()) {
        encryptOnlyKeys.add(keySpec);
      } else {
        bothKeys.add(keySpec);
      }
    }

    int i = (signOnlyKeys.isEmpty() ? 0 : 1) +
        (encryptOnlyKeys.isEmpty() ? 0 : 1) +
        (bothKeys.isEmpty() ? 0 : 1);

    if (i < 2) {
      // if only one category of keyspecs
      return toSingleV2();
    }

    int size = usages.size();

    Set<KeyUsage> signRList    = new HashSet<>(size);
    Set<KeyUsage> signOList    = new HashSet<>(size);
    Set<KeyUsage> encryptRList = new HashSet<>(size);
    Set<KeyUsage> encryptOList = new HashSet<>(size);

    for (Usage u : usages) {
      KeyUsage ku = KeyUsage.getKeyUsage(u.value);
      switch (ku) {
        case dataEncipherment:
        case decipherOnly:
        case encipherOnly:
        case keyAgreement:
        case keyEncipherment:
          (u.required ? encryptRList : encryptOList).add(ku);
          break;
        default:
          (u.required ? signRList : signOList).add(ku);
          break;
      }
    }

    if (encryptOnlyKeys.isEmpty()) {
      // non encrypt keys
      if (encryptRList.isEmpty() && encryptOList.isEmpty()) {
        return toSingleV2();
      }
    }

    List<SingleKeyUsages> list = new ArrayList<>(2);

    SingleKeyUsages defaultSingleKeyUsages = null;
    if (!bothKeys.isEmpty()) {
      List<KeyUsage> required = null;
      if (!signRList.isEmpty() ||!encryptRList.isEmpty()) {
        required = toSortedUsages(signRList, encryptRList);
      }

      List<KeyUsage> optional = null;
      if (!signOList.isEmpty() || !encryptOList.isEmpty()) {
        optional = toSortedUsages(signOList, encryptOList);
      }

      defaultSingleKeyUsages = new SingleKeyUsages(null, required, optional);
      list.add(defaultSingleKeyUsages);
    }

    if (!signOnlyKeys.isEmpty()) {
      List<KeySpec> appliesTo =
          V1XijsonCertprofileType.toSortedKeySpecs(signOnlyKeys);

      List<KeyUsage> required = null;
      if (!signRList.isEmpty()) {
        required = toSortedUsages(signRList);
      }

      List<KeyUsage> optional = null;
      if (!signOList.isEmpty()) {
        optional = toSortedUsages(signOList);
      }

      boolean equalsToDefault = false;
      if (defaultSingleKeyUsages != null) {
        equalsToDefault =
            CompareUtil.equals(
                defaultSingleKeyUsages.getRequired(), required)
            && CompareUtil.equals(
                defaultSingleKeyUsages.getOptional(), optional);
      }

      if (!equalsToDefault) {
        list.add(new SingleKeyUsages(appliesTo, required, optional));
      }
    }

    if (!encryptOnlyKeys.isEmpty()) {
      List<KeySpec> appliesTo =
          V1XijsonCertprofileType.toSortedKeySpecs(encryptOnlyKeys);

      List<KeyUsage> required = null;
      if (!encryptRList.isEmpty()) {
        required = toSortedUsages(encryptRList, Set.of(KeyUsage.keyAgreement));
      }

      List<KeyUsage> optional = null;
      if (!encryptOList.isEmpty()) {
        optional = toSortedUsages(encryptOList, Set.of(KeyUsage.keyAgreement));
      }

      boolean equalsToDefault = false;
      if (defaultSingleKeyUsages != null) {
        equalsToDefault =
            CompareUtil.equals(
                defaultSingleKeyUsages.getRequired(), required)
            && CompareUtil.equals(
                defaultSingleKeyUsages.getOptional(), optional);
      }

      if (!equalsToDefault) {
        list.add(new SingleKeyUsages(appliesTo, required, optional));
      }
    }

    return new org.xipki.ca.certprofile.xijson.conf.extn.KeyUsage(list);
  }

  private static List<KeyUsage> toSortedUsages(
      Set<KeyUsage> set1, Set<KeyUsage> set2) {
    List<KeyUsage> list = new ArrayList<>(set1.size() + set2.size());
    list.addAll(set1);

    for (KeyUsage keyUsage : set2) {
      if (!set1.contains(keyUsage)) {
        list.add(keyUsage);
      }
    }
    Collections.sort(list);
    return list;
  }

  private static List<KeyUsage> toSortedUsages(Set<KeyUsage> keyUsagesSet) {
    List<KeyUsage> list = new ArrayList<>(keyUsagesSet);
    Collections.sort(list);
    return list;
  }

  public static V1KeyUsages parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("usages");
    List<Usage> usages = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      usages.add(Usage.parse(v));
    }

    return new V1KeyUsages(usages);
  }

  public static class Usage {

    private final String value;

    private final boolean required;

    public Usage(String value, boolean required) {
      this.value = value;
      this.required = required;
    }

    public String getValue() {
      return value;
    }

    public static Usage parse(JsonMap json) throws CodecException {
      return new Usage(json.getString("value"),
          json.getBool("required", false));
    }

  }

}
