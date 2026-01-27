// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.OIDs;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.type.Range;
import org.xipki.util.misc.StringUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * Subject DN specification.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class SubjectDnSpec {

  private static final Logger LOG =
      LoggerFactory.getLogger(SubjectDnSpec.class);

  private enum StringControl {
    IA5,
    Printable,
    Utf8,
    PrintableOrUtf8
  }

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

  // according to specification should be 32768, 256 is specified by
  // Lijun Liao (xipki).
  private static final Range RANGE_NAME = new Range(1, 256);

  private static final Map<ASN1ObjectIdentifier, Range> RANGES =
      new HashMap<>();

  private static final Map<ASN1ObjectIdentifier, TextVadidator> PATTERNS =
      new HashMap<>();

  private static final Map<ASN1ObjectIdentifier, StringControl>
      STRING_CONTROLS = new HashMap<>();

  private static final List<ASN1ObjectIdentifier> FORWARD_DNS;

  private static final Set<String> COUNTRY_AREA_CODES = new HashSet<>();

  static {
    // ----- RDN order -----
    BufferedReader reader = getReader("org.xipki.ca.rdnorder.cfg",
        "/conf/rdnorder.cfg");
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
      }
    }

    FORWARD_DNS = Collections.unmodifiableList(tmpForwardDNs);
    if (LOG.isInfoEnabled()) {
      StringBuilder sb = new StringBuilder(500);
      sb.append("forward RDNs: ");
      for (ASN1ObjectIdentifier oid : FORWARD_DNS) {
        String desc = OIDs.getName(oid);
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
      }
    }

    // ----- Type, Length -----
    Set<ASN1ObjectIdentifier> ids = new HashSet<>();

    // businessCategory
    conf(ids, OIDs.DN.businessCategory, RANGE_128,
        StringControl.PrintableOrUtf8);

    // countryName, countryOfCitizenship, countryOfResidence,
    // jurisdictionOfIncorporationCountryName
    ASN1ObjectIdentifier[] idList = new ASN1ObjectIdentifier[] {
        OIDs.DN.country,OIDs. DN.countryOfCitizenship,
        OIDs.DN.countryOfResidence, OIDs.DN.jurIncorporationCountry};
    for (ASN1ObjectIdentifier m : idList) {
      conf(ids, m, RANGE_COUNTRY_NAME, StringControl.Printable);
    }

    // commonName
    conf(ids, OIDs.DN.commonName, RANGE_64, StringControl.PrintableOrUtf8);

    // emailAddress
    conf(ids, OIDs.DN.emailAddress, RANGE_255, StringControl.IA5);

    // DATE_OF_BIRTH
    conf(ids, OIDs.DN.dateOfBirth, RANGE_DATE_OF_BIRTH, null);
    PATTERNS.put(OIDs.DN.dateOfBirth, TextVadidator.DATE_OF_BIRTH);

    // domainComponent
    conf(ids, OIDs.DN.domainComponent, null, StringControl.IA5);

    // RFC 2256 dmdName
    conf(ids, OIDs.DN.dmdName, null, StringControl.PrintableOrUtf8);

    // gender
    conf(ids, OIDs.DN.gender, RANGE_GENDER, StringControl.Printable);
    PATTERNS.put(OIDs.DN.gender, TextVadidator.GENDER);

    // generation qualifier
    conf(ids, OIDs.DN.generationQualifier, RANGE_64,
        StringControl.PrintableOrUtf8);

    // givenName
    conf(ids, OIDs.DN.givenName, RANGE_64, StringControl.PrintableOrUtf8);

    // initials
    conf(ids, OIDs.DN.initials, RANGE_64, StringControl.PrintableOrUtf8);

    // LDAP user ID
    conf(ids, OIDs.DN.userid, null, StringControl.PrintableOrUtf8);

    // localityName, jurisdictionOfIncorporationLocalityName
    idList = new ASN1ObjectIdentifier[] {OIDs.DN.locality,
        OIDs.DN.jurIncorporationLocality};
    for (ASN1ObjectIdentifier m : idList) {
      conf(ids, m, RANGE_128, StringControl.PrintableOrUtf8);
    }

    // name
    conf(ids, OIDs.DN.name, RANGE_NAME, StringControl.PrintableOrUtf8);

    // nameOfBirth
    conf(ids, OIDs.DN.nameAtBirth, RANGE_64, StringControl.PrintableOrUtf8);

    // organizationName
    conf(ids, OIDs.DN.organization, RANGE_64, StringControl.PrintableOrUtf8);

    // organizationIdentifier
    conf(ids, OIDs.DN.organizationIdentifier, RANGE_64,
        StringControl.PrintableOrUtf8);

    // organizationalUnitName
    conf(ids, OIDs.DN.organizationalUnit, RANGE_64,
        StringControl.PrintableOrUtf8);

    // placeOfBirth
    conf(ids, OIDs.DN.placeOfBirth, RANGE_128, StringControl.PrintableOrUtf8);

    // postalAddress
    conf(ids, OIDs.DN.postalAddress, RANGE_POSTAL_ADDRESS, null);

    // postalCode
    conf(ids, OIDs.DN.postalCode, RANGE_POSTAL_CODE,
        StringControl.PrintableOrUtf8);

    // pseudonym
    conf(ids, OIDs.DN.pseudonym, RANGE_64, StringControl.PrintableOrUtf8);

    // distinguishedNameQualifier
    conf(ids, OIDs.DN.dnQualifier, RANGE_64, StringControl.Printable);

    // serialNumber
    conf(ids, OIDs.DN.serialNumber, RANGE_64, StringControl.Printable);

    // stateOrProvinceName, jurisdictionOfIncorporationStateOrProvinceName
    idList = new ASN1ObjectIdentifier[] {OIDs.DN.state,
        OIDs.DN.jurIncorporationState};
    for (ASN1ObjectIdentifier m : idList) {
      conf(ids, m, RANGE_128, StringControl.PrintableOrUtf8);
    }

    // streetAddress
    conf(ids, OIDs.DN.street, RANGE_128, StringControl.PrintableOrUtf8);

    // surName
    conf(ids, OIDs.DN.surname, RANGE_64, StringControl.PrintableOrUtf8);

    // title
    conf(ids, OIDs.DN.title, RANGE_64, StringControl.PrintableOrUtf8);

    // telefonNumber
    conf(ids, OIDs.DN.telephoneNumber, null, StringControl.PrintableOrUtf8);

    // unique Identifier
    conf(ids, OIDs.DN.uniqueIdentifier, null, StringControl.PrintableOrUtf8);

    // unstructedAddress
    conf(ids, OIDs.DN.unstructuredAddress, null, StringControl.PrintableOrUtf8);

    // unstructedName
    conf(ids, OIDs.DN.unstructuredName, null, StringControl.PrintableOrUtf8);
  }

  private SubjectDnSpec() {
  }

  private static void conf(
      Set<ASN1ObjectIdentifier> types, ASN1ObjectIdentifier type, Range range,
      StringControl stringControl) {
    types.add(type);
    if (range != null) {
      RANGES.put(type, range);
    }

    if (stringControl != null) {
      STRING_CONTROLS.put(type, stringControl);
    }
  }

  public static void fixRdnControl(RdnControl control) {
    ASN1ObjectIdentifier type = Args.notNull(control, "control").getType();

    // pattern
    if (control.getPattern() == null && PATTERNS.containsKey(type)) {
      control.setPattern(PATTERNS.get(type));
    }

    // length ranges
    Range specRange = RANGES.get(type);
    if (specRange != null) {
      Range range = control.getStringLengthRange();
      if (range == null) {
        control.setStringLengthRange(specRange);
      } else {
        range.setRange(Math.max(specRange.getMin(), range.getMin()),
            Math.min(specRange.getMax(), range.getMax()));
      }
    }

    StringControl strCtrl = STRING_CONTROLS.get(type);
    if (strCtrl != null) {
      StringType stringType = control.getStringType();
      switch (strCtrl) {
        case IA5:
          control.setStringType(StringType.ia5String);
          break;
        case Printable:
          control.setStringType(StringType.printableString);
          break;
        case Utf8:
          control.setStringType(StringType.utf8String);
          break;
        default: // PrintableOrUtf8:
          if (stringType == null) {
            control.setStringType(StringType.utf8String);
          } else if (stringType != StringType.printableString
                  && stringType != StringType.utf8String) {
            control.setStringType(StringType.utf8String);
          }
      }
    }
  } // method fixRdnControl

  public static List<ASN1ObjectIdentifier> getForwardDNs() {
    return FORWARD_DNS;
  }

  public static boolean isValidCountryAreaCode(String code) {
    Args.notBlank(code, "code");
    return COUNTRY_AREA_CODES.isEmpty()
        || COUNTRY_AREA_CODES.contains(code.toUpperCase());
  }

  private static BufferedReader getReader(
      String propKey, String fallbackResource) {
    String confFile = System.getProperty(propKey);
    if (StringUtil.isNotBlank(confFile)) {
      LOG.info("read from file {}", confFile);
      try {
        return Files.newBufferedReader(Paths.get(confFile));
      } catch (IOException ex) {
        throw new IllegalStateException(
            "could not access non-existing file " + confFile);
      }
    } else {
      InputStream confStream = Optional.ofNullable(
          SubjectDnSpec.class.getResourceAsStream(fallbackResource))
          .orElseThrow(() -> new IllegalStateException(
              "could not access non-existing resource " + fallbackResource));
      LOG.info("read from resource {}", fallbackResource);
      return new BufferedReader(
          new InputStreamReader(confStream, StandardCharsets.UTF_8));
    }
  } // method getReader

}
