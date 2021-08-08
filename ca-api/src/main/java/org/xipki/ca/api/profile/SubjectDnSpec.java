/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.Certprofile.RdnControl;
import org.xipki.ca.api.profile.Certprofile.StringType;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.DN;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/**
 * Subject DN specification.
 *
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
          Collections.singletonList(StringType.printableString));

  private static final Set<StringType> IA5_STRING_ONLY = new HashSet<>(
          Collections.singletonList(StringType.ia5String));

  private static final Map<ASN1ObjectIdentifier, StringType> DFLT_STRING_TYPES = new HashMap<>();

  private static final Map<ASN1ObjectIdentifier, Range> RANGES = new HashMap<>();

  private static final Map<ASN1ObjectIdentifier, TextVadidator> PATTERNS = new HashMap<>();

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
    Set<ASN1ObjectIdentifier> ids = new HashSet<>();

    // businessCategory
    conf(ids, DN.businessCategory, RANGE_128, DIRECTORY_STRINGS);

    // countryName, countryOfCitizenship, countryOfResidence, jurisdictionOfIncorporationCountryName
    ASN1ObjectIdentifier[] idList = new ASN1ObjectIdentifier[] {DN.C, DN.countryOfCitizenship,
        DN.countryOfResidence, DN.jurisdictionOfIncorporationCountryName};
    for (ASN1ObjectIdentifier m : idList) {
      conf(ids, m, RANGE_COUNTRY_NAME, PRINTABLE_STRING_ONLY);
    }

    // commonName
    conf(ids, DN.CN, RANGE_64, DIRECTORY_STRINGS);

    // emailAddress
    conf(ids, DN.emailAddress, RANGE_255, IA5_STRING_ONLY);

    // DATE_OF_BIRTH
    conf(ids, DN.dateOfBirth, RANGE_DATE_OF_BIRTH, null);
    PATTERNS.put(DN.dateOfBirth, TextVadidator.DATE_OF_BIRTH);

    // domainComponent
    conf(ids, DN.DC, null, IA5_STRING_ONLY);

    // RFC 2256 dmdName
    conf(ids, DN.dmdName, null, DIRECTORY_STRINGS);

    // gender
    conf(ids, DN.gender, RANGE_GENDER, PRINTABLE_STRING_ONLY);
    PATTERNS.put(DN.gender, TextVadidator.GENDER);

    // generation qualifier
    conf(ids, DN.generationQualifier, RANGE_64, DIRECTORY_STRINGS);

    // givenName
    conf(ids, DN.givenName, RANGE_64, DIRECTORY_STRINGS);

    // initials
    conf(ids, DN.initials, RANGE_64, DIRECTORY_STRINGS);

    // LDAP user ID
    conf(ids, DN.userid, null, DIRECTORY_STRINGS);

    // localityName, jurisdictionOfIncorporationLocalityName
    idList = new ASN1ObjectIdentifier[] {
        DN.localityName,
        DN.jurisdictionOfIncorporationLocalityName};
    for (ASN1ObjectIdentifier m : idList) {
      conf(ids, m, RANGE_128, DIRECTORY_STRINGS);
    }

    // name
    conf(ids, DN.name, RANGE_NAME, DIRECTORY_STRINGS);

    // nameOfBirth
    conf(ids, DN.nameAtBirth, RANGE_64, DIRECTORY_STRINGS);

    // organizationName
    conf(ids, DN.O, RANGE_64, DIRECTORY_STRINGS);

    // organizationIdentifier
    conf(ids, DN.organizationIdentifier, RANGE_64, DIRECTORY_STRINGS);

    // NIF
    conf(ids, DN.NIF, RANGE_64, DIRECTORY_STRINGS);

    // CIF
    conf(ids, DN.CIF, RANGE_64, DIRECTORY_STRINGS);

    // organizationalUnitName
    conf(ids, DN.OU, RANGE_64, DIRECTORY_STRINGS);

    // placeOfBirth
    conf(ids, DN.placeOfBirth, RANGE_128, DIRECTORY_STRINGS);

    // postalAddress
    conf(ids, DN.postalAddress, RANGE_POSTAL_ADDRESS, DIRECTORY_STRINGS);

    // postalCode
    conf(ids, DN.postalCode, RANGE_POSTAL_CODE, DIRECTORY_STRINGS);

    // pseudonym
    conf(ids, DN.pseudonym, RANGE_64, DIRECTORY_STRINGS);

    // distinguishedNameQualifier
    conf(ids, DN.dnQualifier, RANGE_64, PRINTABLE_STRING_ONLY);

    // serialNumber
    conf(ids, DN.serialNumber, RANGE_64, PRINTABLE_STRING_ONLY);

    // stateOrProvinceName, jurisdictionOfIncorporationStateOrProvinceName
    idList = new ASN1ObjectIdentifier[] {
        DN.ST, DN.jurisdictionOfIncorporationStateOrProvinceName};
    for (ASN1ObjectIdentifier m : idList) {
      conf(ids, m, RANGE_128, DIRECTORY_STRINGS);
    }

    // streetAddress
    conf(ids, DN.street, RANGE_128, DIRECTORY_STRINGS);

    // surName
    conf(ids, DN.surname, RANGE_64, DIRECTORY_STRINGS);

    // title
    conf(ids, DN.T, RANGE_64,DIRECTORY_STRINGS);

    // telefonNumber
    conf(ids, DN.telephoneNumber, null, DIRECTORY_STRINGS);

    // unique Identifier
    conf(ids, DN.uniqueIdentifier, null, DIRECTORY_STRINGS);

    // unstructedAddress
    conf(ids, DN.unstructuredAddress, null, DIRECTORY_STRINGS);

    // unstructedName
    conf(ids, DN.unstructuredName, null, DIRECTORY_STRINGS);

    for (ASN1ObjectIdentifier type : ids) {
      StringType stringType = DFLT_STRING_TYPES.get(type);
      RdnControl control = new RdnControl(type,
          0, // minOccurs
          9 //maxOccurs
          );
      control.setStringType(stringType);
      control.setStringLengthRange(RANGES.get(type));
      TextVadidator pattern = PATTERNS.get(type);
      if (pattern != null) {
        control.setPattern(pattern);
      }
      CONTROLS.put(type, control);
    }
  }

  private SubjectDnSpec() {
  }

  private static void conf(Set<ASN1ObjectIdentifier> types, ASN1ObjectIdentifier type,
      Range range, Set<StringType> stringTypes) {
    types.add(type);
    if (range != null) {
      RANGES.put(type, range);
    }
    if (stringTypes != null) {
      STRING_TYPE_SET.put(type, stringTypes);
      if (stringTypes.size() == 1) {
        DFLT_STRING_TYPES.put(type, stringTypes.iterator().next());
      }
    }
  }

  public static Range getStringLengthRange(ASN1ObjectIdentifier rdnType) {
    return RANGES.get(Args.notNull(rdnType, "rdnType"));
  }

  public static TextVadidator getPattern(ASN1ObjectIdentifier rdnType) {
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
  } // method getRdnControl

  public static void fixRdnControl(RdnControl control)
      throws CertprofileException {
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
    return COUNTRY_AREA_CODES.isEmpty() || COUNTRY_AREA_CODES.contains(code.toUpperCase());
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
  } // method getReader

}
