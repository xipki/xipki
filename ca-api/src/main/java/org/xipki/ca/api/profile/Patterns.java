/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.ca.api.profile;

import java.util.regex.Pattern;

/**
 * TODO.
 * @author Lijun Liao
 */

public class Patterns {

  private Patterns() {
  }

  public static final Pattern COUNTRY = Pattern.compile("[A-Za-z]{2}");

  public static final Pattern DATE_OF_BIRTH =
      Pattern.compile("^(19|20)\\d\\d(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])120000Z");

  public static final Pattern FQDN = Pattern.compile(
      "(?=^.{1,254}$)(^(?:(?!\\d+\\.|-)[a-zA-Z0-9_\\-]{1,63}(?<!-)\\.?)+(?:[a-zA-Z]{2,})$)");

  public static final Pattern GENDER = Pattern.compile("M|m|F|f");

  private static final Pattern NUMBER = Pattern.compile("[\\d]{1,}");

  public static Pattern compile(String pattern) {
    if (":COUNTRY".equalsIgnoreCase(pattern) || "COUNTRY".equalsIgnoreCase(pattern)) {
      return COUNTRY;
    } else if (":DATE_OF_BIRTH".equalsIgnoreCase(pattern)
        || "DATE_OF_BIRTH".equalsIgnoreCase(pattern)) {
      return DATE_OF_BIRTH;
    } else if (":FQDN".equalsIgnoreCase(pattern) || "FQDN".equalsIgnoreCase(pattern)) {
      return FQDN;
    } else if (":GENDER".equalsIgnoreCase(pattern) || "GENDER".equalsIgnoreCase(pattern)) {
      return GENDER;
    } else if (":NUMBER".equalsIgnoreCase(pattern) || "NUMBER".equalsIgnoreCase(pattern)) {
      return NUMBER;
    } else {
      return Pattern.compile(pattern);
    }
  }

}
