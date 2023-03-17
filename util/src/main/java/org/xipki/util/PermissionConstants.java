// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.util.*;
import java.util.Map.Entry;

/**
 * CA permission constants.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class PermissionConstants {

  private static final Map<Integer, String> codeTextMap = new HashMap<>();
  private static final Map<String, Integer> textCodeMap = new HashMap<>();
  private static final List<Integer> permissions;

  public static final int ENROLL_CERT = 1;
  public static final int REVOKE_CERT = 2;
  public static final int UNSUSPEND_CERT = 4;
  public static final int REMOVE_CERT = 8;
  public static final int REENROLL_CERT = 16;
  @Deprecated
  public static final int GEN_CRL = 32;
  public static final int GET_CRL = 64;
  public static final int ENROLL_CROSS = 128;
  public static final int GEN_KEYPAIR = 256;

  public static final int GET_CERT = 512;

  public static final int ALL =
      ENROLL_CERT | REVOKE_CERT | UNSUSPEND_CERT | REMOVE_CERT | REENROLL_CERT
          | GEN_CRL | GET_CRL | ENROLL_CROSS | GEN_KEYPAIR | GET_CERT;

  static {
    codeTextMap.put(ENROLL_CERT, "enroll_cert");
    codeTextMap.put(REVOKE_CERT, "revoke_cert");
    codeTextMap.put(UNSUSPEND_CERT, "unsuspend_cert");
    codeTextMap.put(REMOVE_CERT, "remove_cert");
    codeTextMap.put(REENROLL_CERT, "reenroll_cert");
    codeTextMap.put(GEN_CRL, "gen_crl");
    codeTextMap.put(GET_CRL, "get_crl");
    codeTextMap.put(ENROLL_CROSS, "enroll_cross");
    codeTextMap.put(GEN_KEYPAIR, "gen_keypair");
    codeTextMap.put(GET_CERT, "get_cert");

    for (Entry<Integer, String> entry : codeTextMap.entrySet()) {
      textCodeMap.put(entry.getValue(), entry.getKey());
    }

    List<Integer> tmpPermissions = new ArrayList<>(codeTextMap.keySet());
    Collections.sort(tmpPermissions);
    permissions = Collections.unmodifiableList(tmpPermissions);
  }

  private PermissionConstants() {
  }

  public static boolean contains(int permissionA, int permissionB) {
    return (permissionA & permissionB) == permissionB;
  }

  public static Integer getPermissionForText(String text) {
    if (text == null) {
      return null;
    } else if ("all".equalsIgnoreCase(text)) {
      return ALL;
    } else if (StringUtil.isNumber(text)) {
      return Integer.parseInt(text);
    } else {
      return textCodeMap.get(text.toLowerCase());
    }
  }

  public static String getTextForCode(int code) {
    String text = codeTextMap.get(code);
    return (text == null) ? Integer.toString(code) : text;
  }

  public static List<Integer> getPermissions() {
    return permissions;
  }

  public static String permissionToString(int permission) {
    StringBuilder sb = new StringBuilder();
    for (Entry<Integer, String> entry : codeTextMap.entrySet()) {
      Integer code = entry.getKey();
      if ((permission & code) != 0) {
        sb.append(entry.getValue()).append("|");
      }
    }
    if (sb.length() > 0) {
      // remove the last |
      sb.deleteCharAt(sb.length() - 1);
    }

    return sb.toString();
  }

  public static List<String> permissionToStringSet(int permission) {
    List<String> list = new ArrayList<>(10);
    for (Entry<Integer, String> entry : codeTextMap.entrySet()) {
      Integer code = entry.getKey();
      if ((permission & code) != 0) {
        list.add(entry.getValue());
      }
    }
    Collections.sort(list);
    return list;
  }
}
