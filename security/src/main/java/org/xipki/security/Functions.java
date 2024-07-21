// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * This class contains only static methods. It is the place for all functions
 * that are used by several classes in this package.
 *
 * @author Lijun Liao (xipki)
 */
public class Functions {

  private static class ECInfo {
    int fieldSize;
    int orderSize;
    int orderBitLength;
    String oid;
    String[] names;
    byte[] order;
    byte[] baseX;
  }

  private static final Map<String, ECInfo> ecParamsInfoMap;

  private static final Set<String> edwardsMontgomeryEcParams;

  static {
    edwardsMontgomeryEcParams = new HashSet<>(6);
    // X25519 (1.3.101.110)
    edwardsMontgomeryEcParams.add("06032b656e");
    // X448 (1.3.101.111)
    edwardsMontgomeryEcParams.add("06032b656f");
    // ED25519 (1.3.101.112)
    edwardsMontgomeryEcParams.add("06032b6570");
    // ED448 (1.3.101.113)
    edwardsMontgomeryEcParams.add("06032b6571");

    ecParamsInfoMap = new HashMap<>(120);

    String propFile = "org/xipki/security/EC.properties";
    Properties props = new Properties();
    try {
      props.load(Functions.class.getClassLoader().getResourceAsStream(propFile));
      for (String name : props.stringPropertyNames()) {
        ECInfo ecInfo = new ECInfo();
        ecInfo.oid = name.trim();

        if (ecParamsInfoMap.containsKey(name)) {
          throw new IllegalStateException("duplicated definition of " + name);
        }

        byte[] ecParams = encodeOid(ecInfo.oid);

        String[] values = props.getProperty(name).split(",");
        ecInfo.names = values[0].toUpperCase(Locale.ROOT).split(":");
        ecInfo.fieldSize = (Integer.parseInt(values[1]) + 7) / 8;
        ecInfo.orderBitLength = Integer.parseInt(values[2]);
        ecInfo.orderSize = (ecInfo.orderBitLength + 7) / 8;

        String str = values[3];
        if (!str.isEmpty() && !"-".equals(str)) {
          ecInfo.order = new BigInteger(str, 16).toByteArray();
        }

        str = values[4];
        if (!str.isEmpty() && !"-".equals(str)) {
          ecInfo.baseX = new BigInteger(str, 16).toByteArray();
        }

        String hexEcParams = Hex.encode(ecParams);

        ecParamsInfoMap.put(hexEcParams, ecInfo);
      }
    } catch (Throwable t) {
      throw new IllegalStateException("error reading properties file " + propFile + ": " + t.getMessage());
    }
  }

  private static byte[] encodeOid(String oid) {
    try {
      return new ASN1ObjectIdentifier(oid).getEncoded();
    } catch (IOException e) {
      throw new IllegalArgumentException(e);
    }
  }

  public static Long parseLong(String text) {
    if (text.startsWith("0x") || text.startsWith("0X")) {
      return Long.parseLong(text.substring(2), 16);
    } else {
      boolean isNumber = true;
      boolean withSign = text.startsWith("-");
      for (int i = (withSign ? 1 : 0); i < text.length(); i++) {
        char c = text.charAt(i);
        if (c > '9' || c < '0') {
          isNumber = false;
          break;
        }
      }

      return isNumber ? Long.parseLong(text) : null;
    }
  }

  public static byte[] getEcParams(BigInteger order, BigInteger baseX) {
    byte[] orderBytes = order.toByteArray();
    byte[] baseXBytes = baseX.toByteArray();
    for (Map.Entry<String, ECInfo> m : ecParamsInfoMap.entrySet()) {
      ECInfo ei = m.getValue();
      if (Arrays.equals(ei.order, orderBytes) && Arrays.equals(ei.baseX, baseXBytes)) {
        return Hex.decode(m.getKey());
      }
    }
    return null;
  }

}
