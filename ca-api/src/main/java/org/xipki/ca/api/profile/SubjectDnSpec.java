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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.Certprofile.RdnControl;
import org.xipki.ca.api.profile.Certprofile.StringType;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
public class SubjectDnSpec {

  private static final Logger LOG = LoggerFactory.getLogger(SubjectDnSpec.class);

  /**
   * ranges.
   */
  private static final Range RANGE_64 = new Range(1, 64);

  private static final Range RANGE_128 = new Range(1, 128);

  private static final Range RANGE_255 = new Range(1, 255);

  private static final Range RANGE_POSTAL_CODE = new Range(1, 40);

  private static final Range RANGE_COUNTRY_NAME = new Range(2, 2);

  private static final Range RANGE_POSTAL_ADDRESS = new Range(0, 30);

  private static final Range RANGE_GENDER = new Range(1, 1);

  private static final Range RANGE_DATE_OF_BIRTH = new Range(15, 15);

  // according to specification should be 32768, 256 is specified by XiPKI.
  private static final Range RANGE_NAME = new Range(1, 256);

  // stringTypes
  private static final Set<StringType> DIRECTORY_STRINGS = new HashSet<>(
      Arrays.asList(StringType.bmpString, StringType.printableString,
          StringType.teletexString, StringType.utf8String));

  private static final Set<StringType> PRINTABLE_STRING_ONLY = new HashSet<>(
      Arrays.asList(StringType.printableString));

  private static final Set<StringType> IA5_STRING_ONLY = new HashSet<>(
      Arrays.asList(StringType.ia5String));

  private static final Map<ASN1ObjectIdentifier, StringType> DFLT_STRING_TYPES = new HashMap<>();

  private static final Map<ASN1ObjectIdentifier, Range> RANGES = new HashMap<>();

  private static final Map<ASN1ObjectIdentifier, Pattern> PATTERNS = new HashMap<>();

  private static final Map<ASN1ObjectIdentifier, RdnControl> CONTROLS = new HashMap<>();

  private static final Map<ASN1ObjectIdentifier, Set<StringType>> STRING_TYPE_SET =
      new HashMap<>();

  private static final List<ASN1ObjectIdentifier> FORWARD_DNS;

  private static final Set<String> COUNTRY_AREA_CODES = new HashSet<>();

  static {
    // ----- RDN order -----
    BufferedReader reader = getReader("org.xipki.ca.rdnorder.cfg", "/conf/rdnorder.cfg");
    List<ASN1ObjectIdentifier> tmpForwardDNs = new ArrayList<>(25);
    String line;
    try {
      while ((line = reader.readLine()) != null) {
        line = line.trim();
        if (line.isEmpty() || line.startsWith("#")) {
          continue;
        }

        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(line);
        tmpForwardDNs.add(oid);
      }
    } catch (Exception ex) {
      throw new ExceptionInInitializerError(new Exception(
          "could not load RDN order: " + ex.getMessage(), ex));
    } finally {
      try {
        reader.close();
      } catch (IOException ex) {
        // CHECKSTYLE:SKIP
      }
    }

    FORWARD_DNS = Collections.unmodifiableList(tmpForwardDNs);
    if (LOG.isInfoEnabled()) {
      StringBuilder sb = new StringBuilder(500);
      sb.append("forward RDNs: ");
      for (ASN1ObjectIdentifier oid : FORWARD_DNS) {
        String desc = ObjectIdentifiers.getName(oid);
        if (desc == null) {
          sb.append(oid.getId());
        } else {
          sb.append(desc).append(" (").append(oid.getId()).append("), ");
        }
      }
      if (!FORWARD_DNS.isEmpty()) {
        sb.delete(sb.length() - 2, sb.length());
      }
      LOG.info(sb.toString());
    }

    List<ASN1ObjectIdentifier> tmpBackwardDNs = new ArrayList<>(25);
    int size = tmpForwardDNs.size();
    for (int i = size - 1; i >= 0; i--) {
      tmpBackwardDNs.add(tmpForwardDNs.get(i));
    }

    // ----- country/area code -----
    reader = getReader("org.xipki.ca.areacode.cfg", "/conf/areacode.cfg");
    try {
      while ((line = reader.readLine()) != null) {
        line = line.trim();
        if (line.isEmpty() || line.startsWith("#")) {
          continue;
        }

        StringTokenizer st = new StringTokenizer(line, ";");
        final int n = st.countTokens();
        // 1. country/area name
        // 2. ISO ALPHA-2 code
        // 3. ISO ALPHA-3 code
        // 4. ISO numeric code
        if (n != 4) {
          LOG.warn("invalid country/area line {}", line);
          continue;
        }

        // skip the name
        st.nextToken();
        String areaCode = st.nextToken().trim();
        COUNTRY_AREA_CODES.add(areaCode.toUpperCase());
      }

      if (LOG.isInfoEnabled()) {
        List<String> list = new ArrayList<>(COUNTRY_AREA_CODES);
        Collections.sort(list);
        LOG.info("area/country codes: {}", list);
      }
    } catch (Exception ex) {
      throw new ExceptionInInitializerError(new Exception(
          "could not load area code: " + ex.getMessage(), ex));
    } finally {
      try {
        reader.close();
      } catch (IOException ex) {
        // CHECKSTYLE:SKIP
      }
    }

    // ----- Type, Length -----
    ASN1ObjectIdentifier id;

    Set<ASN1ObjectIdentifier> ids = new HashSet<>();

    // businessCategory
    id = ObjectIdentifiers.DN.businessCategory;
    ids.add(id);
    RANGES.put(id, RANGE_128);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // countryName
    id = ObjectIdentifiers.DN.C;
    ids.add(id);
    RANGES.put(id, RANGE_COUNTRY_NAME);
    STRING_TYPE_SET.put(id, PRINTABLE_STRING_ONLY);
    DFLT_STRING_TYPES.put(id, StringType.printableString);

    // commonName
    id = ObjectIdentifiers.DN.CN;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // emailAddress
    id = ObjectIdentifiers.DN.emailAddress;
    ids.add(id);
    RANGES.put(id, RANGE_255);
    STRING_TYPE_SET.put(id, IA5_STRING_ONLY);
    DFLT_STRING_TYPES.put(id, StringType.ia5String);

    // countryOfCitizenship
    id = ObjectIdentifiers.DN.countryOfCitizenship;
    ids.add(id);
    RANGES.put(id, RANGE_COUNTRY_NAME);
    PATTERNS.put(id, Patterns.COUNTRY);
    STRING_TYPE_SET.put(id, PRINTABLE_STRING_ONLY);
    DFLT_STRING_TYPES.put(id, StringType.printableString);

    // countryOfResidence
    id = ObjectIdentifiers.DN.countryOfResidence;
    ids.add(id);
    RANGES.put(id, RANGE_COUNTRY_NAME);
    PATTERNS.put(id, Patterns.COUNTRY);
    STRING_TYPE_SET.put(id, PRINTABLE_STRING_ONLY);
    DFLT_STRING_TYPES.put(id, StringType.printableString);

    // DATE_OF_BIRTH
    id = ObjectIdentifiers.DN.dateOfBirth;
    ids.add(id);
    RANGES.put(id, RANGE_DATE_OF_BIRTH);
    PATTERNS.put(id, Patterns.DATE_OF_BIRTH);

    // domainComponent
    id = ObjectIdentifiers.DN.DC;
    ids.add(id);
    STRING_TYPE_SET.put(id, IA5_STRING_ONLY);
    DFLT_STRING_TYPES.put(id, StringType.ia5String);

    // RFC 2256 dmdName
    id = ObjectIdentifiers.DN.dmdName;
    ids.add(id);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // gender
    id = ObjectIdentifiers.DN.gender;
    ids.add(id);
    PATTERNS.put(id, Patterns.GENDER);
    RANGES.put(id, RANGE_GENDER);
    STRING_TYPE_SET.put(id, PRINTABLE_STRING_ONLY);
    DFLT_STRING_TYPES.put(id, StringType.printableString);

    // generation qualifier
    id = ObjectIdentifiers.DN.generationQualifier;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // givenName
    id = ObjectIdentifiers.DN.givenName;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // initials
    id = ObjectIdentifiers.DN.initials;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // LDAP user ID
    id = ObjectIdentifiers.DN.ldapUid;
    ids.add(id);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // localityName
    id = ObjectIdentifiers.DN.localityName;
    ids.add(id);
    RANGES.put(id, RANGE_128);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // name
    id = ObjectIdentifiers.DN.name;
    ids.add(id);
    RANGES.put(id, RANGE_NAME);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // nameOfBirth
    id = ObjectIdentifiers.DN.nameAtBirth;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // organizationName
    id = ObjectIdentifiers.DN.O;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // organizationIdentifier
    id = ObjectIdentifiers.DN.organizationIdentifier;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // NIF
    id = ObjectIdentifiers.DN.NIF;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // CIF
    id = ObjectIdentifiers.DN.CIF;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // organizationalUnitName
    id = ObjectIdentifiers.DN.OU;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // placeOfBirth
    id = ObjectIdentifiers.DN.placeOfBirth;
    ids.add(id);
    RANGES.put(id, RANGE_128);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // postalAddress
    id = ObjectIdentifiers.DN.postalAddress;
    ids.add(id);
    RANGES.put(id, RANGE_POSTAL_ADDRESS);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // postalCode
    id = ObjectIdentifiers.DN.postalCode;
    ids.add(id);
    RANGES.put(id, RANGE_POSTAL_CODE);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // pseudonym
    id = ObjectIdentifiers.DN.pseudonym;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // distinguishedNameQualifier
    id = ObjectIdentifiers.DN.dnQualifier;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, PRINTABLE_STRING_ONLY);
    DFLT_STRING_TYPES.put(id, StringType.printableString);

    // serialNumber
    id = ObjectIdentifiers.DN.serialNumber;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, PRINTABLE_STRING_ONLY);
    DFLT_STRING_TYPES.put(id, StringType.printableString);

    // stateOrProvinceName
    id = ObjectIdentifiers.DN.ST;
    ids.add(id);
    RANGES.put(id, RANGE_128);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // streetAddress
    id = ObjectIdentifiers.DN.street;
    ids.add(id);
    RANGES.put(id, RANGE_128);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // surName
    id = ObjectIdentifiers.DN.surname;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // title
    id = ObjectIdentifiers.DN.T;
    ids.add(id);
    RANGES.put(id, RANGE_64);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // telefonNumber
    id = ObjectIdentifiers.DN.telephoneNumber;
    ids.add(id);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // unique Identifier
    id = ObjectIdentifiers.DN.uniqueIdentifier;
    ids.add(id);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // unstructedAddress
    id = ObjectIdentifiers.DN.unstructuredAddress;
    ids.add(id);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    // unstructedName
    id = ObjectIdentifiers.DN.unstructuredName;
    ids.add(id);
    STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
    DFLT_STRING_TYPES.put(id, StringType.utf8String);

    for (ASN1ObjectIdentifier type : ids) {
      StringType stringType = DFLT_STRING_TYPES.get(type);
      if (stringType == null) {
        stringType = StringType.utf8String;
      }
      RdnControl control = new RdnControl(type,
          0, // minOccurs
          9 //maxOccurs
          );
      control.setStringType(stringType);
      control.setStringLengthRange(RANGES.get(type));
      Pattern pattern = PATTERNS.get(type);
      if (pattern != null) {
        control.setPattern(pattern);
      }
      CONTROLS.put(type, control);
    }
  }

  private SubjectDnSpec() {
  }

  public static Range getStringLengthRange(ASN1ObjectIdentifier rdnType) {
    return RANGES.get(Args.notNull(rdnType, "rdnType"));
  }

  public static Pattern getPattern(ASN1ObjectIdentifier rdnType) {
    return PATTERNS.get(Args.notNull(rdnType, "rdnType"));
  }

  public static StringType getStringType(ASN1ObjectIdentifier rdnType) {
    return DFLT_STRING_TYPES.get(Args.notNull(rdnType, "rdnType"));
  }

  public static RdnControl getRdnControl(ASN1ObjectIdentifier rdnType) {
    RdnControl control = CONTROLS.get(Args.notNull(rdnType, "rdnType"));
    if (control == null) {
      // minOccurs = 0, maxOccurs = 9
      control = new RdnControl(rdnType, 0, 9);
      control.setStringType(StringType.utf8String);
    }
    return control;
  } // static

  public static void fixRdnControl(RdnControl control) throws CertprofileException {
    Args.notNull(control, "control");

    ASN1ObjectIdentifier type = control.getType();
    StringType stringType = control.getStringType();
    if (stringType != null) {
      if (STRING_TYPE_SET.containsKey(type) && !STRING_TYPE_SET.get(type).contains(stringType)) {
        throw new CertprofileException(
          String.format("%s is not allowed %s", stringType.name(), type.getId()));
      }
    } else {
      StringType specStrType = DFLT_STRING_TYPES.get(type);
      if (specStrType != null) {
        control.setStringType(specStrType);
      }
    }

    if (control.getPattern() == null && PATTERNS.containsKey(type)) {
      control.setPattern(PATTERNS.get(type));
    }

    Range specRange = RANGES.get(type);
    if (specRange == null) {
      control.setStringLengthRange(null);
      return;
    }

    Range isRange = control.getStringLengthRange();
    if (isRange == null) {
      control.setStringLengthRange(specRange);
      return;
    }

    boolean changed = false;
    Integer specMin = specRange.getMin();
    Integer min = isRange.getMin();
    if (min == null) {
      changed = true;
      min = specMin;
    } else if (specMin != null && specMin > min) {
      changed = true;
      min = specMin;
    }

    Integer specMax = specRange.getMax();
    Integer max = isRange.getMax();
    if (max == null) {
      changed = true;
      max = specMax;
    } else if (specMax != null && specMax < max) {
      changed = true;
      max = specMax;
    }

    if (changed) {
      isRange.setRange(min, max);
    } // isRange
  } // method fixRdnControl

  public static List<ASN1ObjectIdentifier> getForwardDNs() {
    return FORWARD_DNS;
  }

  public static boolean isValidCountryAreaCode(String code) {
    Args.notBlank(code, "code");
    return COUNTRY_AREA_CODES.isEmpty() ? true : COUNTRY_AREA_CODES.contains(code.toUpperCase());
  }

  private static BufferedReader getReader(String propKey, String fallbackResource) {
    String confFile = System.getProperty(propKey);
    if (StringUtil.isNotBlank(confFile)) {
      LOG.info("read from file " + confFile);
      try {
        return Files.newBufferedReader(Paths.get(confFile));
      } catch (IOException ex) {
        throw new IllegalStateException("could not access non-existing file " + confFile);
      }
    } else {
      InputStream confStream = SubjectDnSpec.class.getResourceAsStream(fallbackResource);
      if (confStream == null) {
        throw new IllegalStateException(
            "could not access non-existing resource " + fallbackResource);
      }
      LOG.info("read from resource " + fallbackResource);
      return new BufferedReader(new InputStreamReader(confStream));
    }
  }

}
