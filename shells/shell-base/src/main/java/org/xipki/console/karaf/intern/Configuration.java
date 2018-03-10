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

package org.xipki.console.karaf.intern;

import java.io.File;
import java.nio.charset.Charset;

/**
 * Provides access to configuration values.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Configuration {

  private Configuration() {
  }

  public static String getLineSeparator() {
    return System.getProperty("line.separator");
  }

  public static File getUserHome() {
    return new File(System.getProperty("user.home"));
  }

  public static String getOsName() {
    return System.getProperty("os.name").toLowerCase();
  }

  public static boolean isWindows() {
    return getOsName().startsWith("windows");
  }

  public static String getFileEncoding() {
    return System.getProperty("file.encoding");
  }

  /**
   * Get the default encoding. Will first look at the LC_CTYPE environment variable, then the
   * input.encoding system property, then the default charset according to the JVM.
   *
   * @return The default encoding to use when none is specified.
   */
  public static String getEncoding() {
    // LC_CTYPE is usually in the form en_US.UTF-8
    String envEncoding = extractEncodingFromCtype(System.getenv("LC_CTYPE"));
    if (envEncoding != null) {
      return envEncoding;
    }
    return System.getProperty("input.encoding", Charset.defaultCharset().name());
  }

  /**
   * Parses the LC_CTYPE value to extract the encoding according to the POSIX standard, which
   * says that the LC_CTYPE environment variable may be of the format
   * <code>[language[_territory][.codeset][@modifier]]</code>.
   *
   * @param ctype The ctype to parse, may be null
   * @return The encoding, if one was present, otherwise null
   */
  static String extractEncodingFromCtype(final String ctype) {
    if (ctype != null && ctype.indexOf('.') > 0) {
      String encodingAndModifier = ctype.substring(ctype.indexOf('.') + 1);
      return (encodingAndModifier.indexOf('@') > 0)
        ? encodingAndModifier.substring(0, encodingAndModifier.indexOf('@'))
        : encodingAndModifier;
    }
    return null;
  }

}
