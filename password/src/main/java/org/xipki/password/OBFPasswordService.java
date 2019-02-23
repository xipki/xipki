/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.password;

import java.nio.charset.StandardCharsets;

import org.xipki.util.Args;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class OBFPasswordService {

  public static final String OBFUSCATE = "OBF:";

  public static String obfuscate(String str) {
    Args.notNull(str, "str");
    StringBuilder buf = new StringBuilder();
    byte[] bytes = StringUtil.toUtf8Bytes(str);

    buf.append(OBFUSCATE);
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
  }

  public static String deobfuscate(String str) {
    Args.notNull(str, "str");

    if (startsWithIgnoreCase(str, OBFUSCATE)) {
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
  }

  private static boolean startsWithIgnoreCase(String str, String prefix) {
    return (str.length() < prefix.length()) ? false
        : prefix.equalsIgnoreCase(str.substring(0, prefix.length()));
  }

}
