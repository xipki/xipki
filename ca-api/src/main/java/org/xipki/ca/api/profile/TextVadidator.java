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

import org.xipki.util.LruCache;

/**
 * Text validator.
 *
 * @author Lijun Liao
 */

public abstract class TextVadidator {

  private TextVadidator() {
  }

  public abstract boolean isValid(String value);

  public abstract String pattern();

  private static class RegexValidator extends TextVadidator {

    private final Pattern pattern;

    RegexValidator(String regex) {
      this.pattern = Pattern.compile(regex);
    }

    @Override
    public boolean isValid(String value) {
      return pattern.matcher(value).matches();
    }

    @Override
    public String pattern() {
      return pattern.pattern();
    }

  }

  // CHECKSTYLE:SKIP
  private static class FQDNValidator extends TextVadidator {

    @Override
    public boolean isValid(String value) {
      return DomainValidator.getInstance().isValid(value);
    }

    @Override
    public String pattern() {
      return ":FQDN";
    }

  }

  public static final TextVadidator COUNTRY = new RegexValidator("[A-Za-z]{2}");

  public static final TextVadidator NUMBER = new RegexValidator("[\\d]{1,}");

  public static final TextVadidator DATE_OF_BIRTH =
      new RegexValidator("^(19|20)\\d\\d(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])120000Z");

  public static final TextVadidator GENDER = new RegexValidator("M|m|F|f");

  public static final TextVadidator FQDN = new FQDNValidator();

  private static final LruCache<String, TextVadidator> cache = new LruCache<>(200);

  public static TextVadidator compile(String regex) {
    if (":COUNTRY".equalsIgnoreCase(regex) || "COUNTRY".equalsIgnoreCase(regex)) {
      return COUNTRY;
    } else if (":DATE_OF_BIRTH".equalsIgnoreCase(regex)
        || "DATE_OF_BIRTH".equalsIgnoreCase(regex)) {
      return DATE_OF_BIRTH;
    } else if (":FQDN".equalsIgnoreCase(regex) || "FQDN".equalsIgnoreCase(regex)) {
      return FQDN;
    } else if (":GENDER".equalsIgnoreCase(regex) || "GENDER".equalsIgnoreCase(regex)) {
      return GENDER;
    } else if (":NUMBER".equalsIgnoreCase(regex) || "NUMBER".equalsIgnoreCase(regex)) {
      return NUMBER;
    } else {
      TextVadidator validator = cache.get(regex);
      if (validator == null) {
        validator = new RegexValidator(regex);
        cache.put(regex, validator);
      }
      return validator;
    }
  }

}
