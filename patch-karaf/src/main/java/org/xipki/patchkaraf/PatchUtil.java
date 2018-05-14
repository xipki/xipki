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

package org.xipki.patchkaraf;

import java.io.BufferedReader;
import java.io.IOException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.1.0
 */

class PatchUtil {

  public static boolean isBlank(String str) {
    return str == null || str.isEmpty();
  }

  public static String readContinuedLine(BufferedReader reader, String startLine)
      throws IOException {
    if (!startLine.endsWith("\\")) {
      return startLine;
    }

    StringBuilder buf = new StringBuilder();
    buf.append(startLine.substring(0, startLine.length() - 1));

    String line;
    while ((line = reader.readLine()) != null) {
      if (!line.endsWith("\\")) {
        buf.append(line);
        break;
      }

      buf.append(line.substring(0, line.length() - 1));
    }

    return buf.toString();
  }

  public static String commentContinuedLine(BufferedReader reader, String startLine)
      throws IOException {
    if (!startLine.endsWith("\\")) {
      return "#" + startLine;
    }

    StringBuilder buf = new StringBuilder();
    buf.append("#").append(startLine).append("\n");;

    String line;
    while ((line = reader.readLine()) != null) {
      if (!line.endsWith("\\")) {
        buf.append("#").append(line);
        break;
      }

      buf.append("#").append(line).append("\n");
    }

    return buf.toString();
  }

}
