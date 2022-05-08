/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.xipki.util.StringUtil;

import java.util.*;

import static org.xipki.util.Args.*;

/**
 * Algorithm utility class.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class AlgorithmUtil {

  private static final List<String> curveNames;

  private static final Map<String, ASN1ObjectIdentifier> curveNameToOidMap;

  private static final Map<ASN1ObjectIdentifier, String> curveOidToNameMap;

  static {
    {
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
      curveNameToOidMap = Collections.unmodifiableMap(nameOidMap);
      curveOidToNameMap = Collections.unmodifiableMap(oidNameMap);
    }
  } // method static

  private AlgorithmUtil() {
  }

  public static boolean equalsAlgoName(String algoNameA, String algoNameB) {
    notBlank(algoNameA, "algoNameA");
    notBlank(algoNameB, "algoNameB");
    if (algoNameA.equalsIgnoreCase(algoNameB)) {
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
    notBlank(algoName, "algoName");
    String tmpAlgoName = algoName.toUpperCase();
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
    return curveNameToOidMap.get(toNonBlankLower(curveName, "curveName"));
  } // method getCurveOidForName

  public static List<String> getECCurveNames() {
    return curveNames;
  }

  public static String getCurveName(ASN1ObjectIdentifier curveOid) {
    notNull(curveOid, "curveOid");
    return curveOidToNameMap.get(curveOid);
  }

  public static ASN1ObjectIdentifier getCurveOidForCurveNameOrOid(String curveNameOrOid) {
    notBlank(curveNameOrOid, "curveNameOrOid");
    ASN1ObjectIdentifier oid;
    try {
      oid = new ASN1ObjectIdentifier(curveNameOrOid);
    } catch (Exception ex) {
      oid = getCurveOidForName(curveNameOrOid);
    }
    return oid;
  } // method getCurveOidForCurveNameOrOid

}
