// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Domain validator.
 *
 * @author Lijun Liao (xipki)
 *
 */
class DomainValidator {

  static class RegexValidator {

    private final Pattern pattern;

    /**
     * Construct a validator that matches any one of the set of regular
     * expressions with the specified case sensitivity.
     *
     * @param regex The regular expressions this validator will validate against
     * @param caseSensitive when <code>true</code> matching is <i>case
     * sensitive</i>, otherwise matching is <i>case in-sensitive</i>
     */
    public RegexValidator(String regex, boolean caseSensitive) {
      if (regex == null || regex.isEmpty()) {
        throw new IllegalArgumentException("Regular expression is missing");
      }
      int flags =  (caseSensitive ? 0 : Pattern.CASE_INSENSITIVE);
      pattern = Pattern.compile(regex, flags);
    }

    /**
     * Validate a value against the set of regular expressions
     * returning the array of matched groups.
     *
     * @param value The value to validate.
     * @return String array of the <i>groups</i> matched if
     *         valid or <code>null</code> if invalid.
     */
    public String[] match(String value) {
      if (value == null) {
        return null;
      }

      Matcher matcher = pattern.matcher(value);
      if (matcher.matches()) {
        int count = matcher.groupCount();
        String[] groups = new String[count];
        for (int j = 0; j < count; j++) {
          groups[j] = matcher.group(j + 1);
        }
        return groups;
      }

      return null;
    } // method match

  } // class RegexValidator

  // Regular expression strings for hostnames (derived from RFC2396 and RFC 1123)
  private static final String DOMAIN_LABEL_REGEX = "\\p{Alnum}(?>[\\p{Alnum}-]*\\p{Alnum})*";
  private static final String TOP_LABEL_REGEX = "\\p{Alpha}{2,}";
  private static final String DOMAIN_NAME_REGEX = "^(?:" + DOMAIN_LABEL_REGEX + "\\.)+" + "(" + TOP_LABEL_REGEX + ")$";

  /**
   * Singleton instance of this validator.
   */
  private static final DomainValidator DOMAIN_VALIDATOR = new DomainValidator();

  /**
   * RegexValidator for matching domains.
   */
  private final RegexValidator domainRegex = new RegexValidator(DOMAIN_NAME_REGEX, true);

  /**
   * Returns the singleton instance of this validator.
   * @return the singleton instance of this validator
   */
  public static DomainValidator getInstance() {
    return DOMAIN_VALIDATOR;
  }

  /** Private constructor. */
  private DomainValidator() {}

  /**
   * Returns true if the specified <code>String</code> parses
   * as a valid domain name with a recognized top-level domain.
   * The parsing is case-sensitive.
   * @param domain the parameter to check for domain name syntax
   * @return true if the parameter is a valid domain name
   */
  public boolean isValid(String domain) {
    String[] groups = domainRegex.match(domain.startsWith("*.") ? domain.substring(2) : domain);
    return groups != null && groups.length > 0;
  }

}
