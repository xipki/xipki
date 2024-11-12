// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

import java.nio.charset.StandardCharsets;

/**
 * OBF (jetty's Obfuscate) password service.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */
public class OBFPasswordService {

  public static final String PROTOCOL_OBF = "OBF";

  public static String obfuscate(String str) {
    Args.notNull(str, "str");
    StringBuilder buf = new StringBuilder();
    byte[] bytes = Args.toUtf8Bytes(str);

    buf.append(PROTOCOL_OBF).append(":");
    for (int i = 0; i < bytes.length; i++) {
      byte b1 = bytes[i];
      byte b2 = bytes[bytes.length - (i + 1)];
      if (b1 < 0 || b2 < 0) {
        int i0 = (0xff & b1) * 256 + (0xff & b2);
        String sx = Integer.toString(i0, 36).toLowerCase();
        buf.append("U0000", 0, 5 - sx.length());
        buf.append(sx);
      } else {
        int i1 = 127 + b1 + b2;
        int i2 = 127 + b1 - b2;
        int i0 = i1 * 256 + i2;
        String sx = Integer.toString(i0, 36).toLowerCase();

        buf.append("000", 0, 4 - sx.length());
        buf.append(sx);
      }
    } // end for
    return buf.toString();
  } // method obfuscate

  public static String deobfuscate(String str) {
    Args.notNull(str, "str");

    if (startsWithIgnoreCase(str, PROTOCOL_OBF + ":")) {
      str = str.substring(4);
    }

    byte[] bytes = new byte[str.length() / 2];
    int idx = 0;
    for (int i = 0; i < str.length(); i += 4) {
      if (str.charAt(i) == 'U') {
        i++;
        String sx = str.substring(i, i + 4);
        int i0 = Integer.parseInt(sx, 36);
        byte bx = (byte) (i0 >> 8);
        bytes[idx++] = bx;
      } else {
        String sx = str.substring(i, i + 4);
        int i0 = Integer.parseInt(sx, 36);
        int i1 = (i0 / 256);
        int i2 = (i0 % 256);
        byte bx = (byte) ((i1 + i2 - 254) / 2);
        bytes[idx++] = bx;
      }
    } // end for

    return new String(bytes, 0, idx, StandardCharsets.UTF_8);
  } // method deobfuscate

  private static boolean startsWithIgnoreCase(String str, String prefix) {
    return str.length() >= prefix.length() && prefix.equalsIgnoreCase(str.substring(0, prefix.length()));
  }

}
