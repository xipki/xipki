// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.xipki.security.EdECConstants;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Algorithm utility class.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class AlgorithmUtil {

  private static final List<String> curveNames;

  private static final List<ASN1ObjectIdentifier> curveOIDs;

  private static final Map<String, ASN1ObjectIdentifier> curveNameToOidMap;

  private static final Map<ASN1ObjectIdentifier, String> curveOidToNameMap;

  static {
    //----- initialize the static fields curveNames, curveNameOidMap, curveOidNameMap
    Map<String, ASN1ObjectIdentifier> nameOidMap = new HashMap<>();

    Enumeration<?> names = ECNamedCurveTable.getNames();
    List<String> nameList = new LinkedList<>();
    while (names.hasMoreElements()) {
      String name = ((String) names.nextElement()).toLowerCase();
      ASN1ObjectIdentifier oid = org.bouncycastle.asn1.x9.ECNamedCurveTable.getOID(name);
      if (oid == null) {
        continue;
      }

      nameList.add(name);
      nameOidMap.put(name, oid);
    }

    Map<ASN1ObjectIdentifier, String> oidNameMap = new HashMap<>();

    // X962, SEC and NIST give the same curve different name, we use here only NIST names
    @SuppressWarnings("rawtypes")
    Enumeration nistNames = NISTNamedCurves.getNames();
    while (nistNames.hasMoreElements()) {
      String nistName = (String) nistNames.nextElement();
      ASN1ObjectIdentifier oid = NISTNamedCurves.getOID(nistName);
      oidNameMap.put(oid, nistName);
    }

    for (String name : nameList) {
      ASN1ObjectIdentifier oid = nameOidMap.get(name);

      nameOidMap.put(name, oid);
      if (!oidNameMap.containsKey(oid)) {
        oidNameMap.put(oid, name);
      }
    }

    Collections.sort(nameList);
    curveNames = Collections.unmodifiableList(nameList);
    curveOIDs = List.copyOf(oidNameMap.keySet());
    curveNameToOidMap = Collections.unmodifiableMap(nameOidMap);
    curveOidToNameMap = Collections.unmodifiableMap(oidNameMap);
  } // method static

  private AlgorithmUtil() {
  }

  public static boolean equalsAlgoName(String algoNameA, String algoNameB) {
    if (Args.notBlank(algoNameA, "algoNameA")
        .equalsIgnoreCase(Args.notBlank(algoNameB, "algoNameB"))) {
      return true;
    }

    String tmpA = algoNameA;
    if (tmpA.indexOf('-') != -1) {
      tmpA = tmpA.replace("-", "");
    }

    String tmpB = algoNameB;
    if (tmpB.indexOf('-') != -1) {
      tmpB = tmpB.replace("-", "");
    }

    if (tmpA.equalsIgnoreCase(tmpB)) {
      return true;
    }

    return splitAlgoNameTokens(tmpA).equals(splitAlgoNameTokens(tmpB));
  } // method equalsAlgoName

  private static Set<String> splitAlgoNameTokens(String algoName) {
    String tmpAlgoName = Args.notBlank(algoName, "algoName").toUpperCase();
    int idx = tmpAlgoName.indexOf("AND");
    Set<String> set = new HashSet<>();

    if (idx == -1) {
      set.add(tmpAlgoName);
      return set;
    }

    final int len = tmpAlgoName.length();

    int beginIndex = 0;
    int endIndex = idx;
    while (true) {
      String token = tmpAlgoName.substring(beginIndex, endIndex);
      if (StringUtil.isNotBlank(token)) {
        set.add(token);
      }

      if (endIndex >= len) {
        return set;
      }
      beginIndex = endIndex + 3; // 3 = "AND".length()
      endIndex = tmpAlgoName.indexOf("AND", beginIndex);
      if (endIndex == -1) {
        endIndex = len;
      }
    }
  } // method splitAlgoNameTokens

  private static ASN1ObjectIdentifier getCurveOidForName(String curveName) {
    return curveNameToOidMap.get(Args.toNonBlankLower(curveName, "curveName"));
  } // method getCurveOidForName

  public static List<String> getECCurveNames() {
    return curveNames;
  }

  public static List<ASN1ObjectIdentifier> getECCurveOIDs() {
    return curveOIDs;
  }

  public static String getCurveName(ASN1ObjectIdentifier curveOid) {
    String curveName = curveOidToNameMap.get(Args.notNull(curveOid, "curveOid"));
    if (curveName == null) {
      curveName = EdECConstants.getName(curveOid);
    }
    return curveName;
  }

  public static ASN1ObjectIdentifier getCurveOidForCurveNameOrOid(String curveNameOrOid) {
    ASN1ObjectIdentifier oid;
    try {
      oid = new ASN1ObjectIdentifier(Args.notBlank(curveNameOrOid, "curveNameOrOid"));
    } catch (Exception ex) {
      oid = getCurveOidForName(curveNameOrOid);
      if (oid == null) {
        oid = EdECConstants.getCurveOid(curveNameOrOid);
      }
    }
    return oid;
  } // method getCurveOidForCurveNameOrOid

}
