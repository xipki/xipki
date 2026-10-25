// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.asn1.oid.MatterOIDs;
import org.xipki.codec.asn1.oid.OIDs;
import org.xipki.codec.util.Args;
import org.xipki.ca.api.Range;
import org.xipki.pkix.util.misc.StringUtil;

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
 * Subject DN Spec.
 *
 * @author Lijun Liao (xipki)
 */
public class SubjectDnSpec {

  private static final Logger LOG = LoggerFactory.getLogger(SubjectDnSpec.class);

  private enum StringControl {
    IA5,
    Printable,
    Utf8,
    PrintableOrUtf8
  }

  /**
   * ranges.
   */
  private static final Range RANGE_1_64 = new Range(1, 64);

  private static final Range RANGE_1_128 = new Range(1, 128);

  private static final Range RANGE_1_255 = new Range(1, 255);

  private static final Range RANGE_POSTAL_CODE = new Range(1, 40);

  private static final Range RANGE_COUNTRY_NAME = new Range(2, 2);

  private static final Range RANGE_POSTAL_ADDRESS = new Range(0, 30);

  private static final Range RANGE_GENDER = new Range(1, 1);

  private static final Range RANGE_DATE_OF_BIRTH = new Range(15, 15);

  // according to specification should be 32768, 256 is specified by
  // Lijun Liao (xipki).
  private static final Range RANGE_NAME = new Range(1, 256);

  private static final Range RANGE_4_4 = new Range(4, 4);

  private static final Range RANGE_8_8 = new Range(8, 8);

  private static final Range RANGE_16_16 = new Range(16, 16);

  private static final Map<Asn1Oid, Range> RANGES = new HashMap<>();

  private static final Map<Asn1Oid, TextValidator> PATTERNS = new HashMap<>();

  private static final Map<Asn1Oid, StringControl> STRING_CONTROLS = new HashMap<>();

  private static final List<Asn1Oid> FORWARD_DNS;

  private static final Set<String> COUNTRY_AREA_CODES = new HashSet<>();

  static {
    // ----- RDN order -----
    BufferedReader reader = getReader("org.xipki.ca.rdnorder.cfg", "/conf/rdnorder.cfg");
    List<Asn1Oid> tmpForwardDNs = new ArrayList<>(25);
    String line;
    try {
      while ((line = reader.readLine()) != null) {
        line = line.trim();
        if (line.isEmpty() || line.startsWith("#")) {
          continue;
        }

        tmpForwardDNs.add(new Asn1Oid(line));
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
      for (Asn1Oid oid : FORWARD_DNS) {
        sb.append(OIDs.oidToDisplayName(oid)).append(", ");
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
    Set<Asn1Oid> ids = new HashSet<>();

    // businessCategory
    conf(ids, AttributeOIDs.businessCategory, RANGE_1_128, StringControl.PrintableOrUtf8);

    // countryName, countryOfCitizenship, countryOfResidence,
    // jurisdictionOfIncorporationCountryName
    Asn1Oid[] idList = new Asn1Oid[] {
        AttributeOIDs.country, AttributeOIDs.countryOfCitizenship,
        AttributeOIDs.countryOfResidence, AttributeOIDs.jurIncorporationCountry};
    for (Asn1Oid m : idList) {
      conf(ids, m, RANGE_COUNTRY_NAME, StringControl.Printable);
    }

    // commonName
    conf(ids, AttributeOIDs.commonName, RANGE_1_64, StringControl.PrintableOrUtf8);

    // emailAddress
    conf(ids, AttributeOIDs.emailAddress, RANGE_1_255, StringControl.IA5);

    // DATE_OF_BIRTH
    conf(ids, AttributeOIDs.dateOfBirth, RANGE_DATE_OF_BIRTH, null);
    PATTERNS.put(AttributeOIDs.dateOfBirth, TextValidator.DATE_OF_BIRTH);

    // domainComponent
    conf(ids, AttributeOIDs.domainComponent, null, StringControl.IA5);

    // RFC 2256 dmdName
    conf(ids, AttributeOIDs.dmdName, null, StringControl.PrintableOrUtf8);

    // gender
    conf(ids, AttributeOIDs.gender, RANGE_GENDER, StringControl.Printable);
    PATTERNS.put(AttributeOIDs.gender, TextValidator.GENDER);

    // generation qualifier
    conf(ids, AttributeOIDs.generationQualifier, RANGE_1_64, StringControl.PrintableOrUtf8);

    // givenName
    conf(ids, AttributeOIDs.givenName, RANGE_1_64, StringControl.PrintableOrUtf8);

    // initials
    conf(ids, AttributeOIDs.initials, RANGE_1_64, StringControl.PrintableOrUtf8);

    // LDAP user ID
    conf(ids, AttributeOIDs.userid, null, StringControl.PrintableOrUtf8);

    // localityName, jurisdictionOfIncorporationLocalityName
    idList = new Asn1Oid[] {AttributeOIDs.locality, AttributeOIDs.jurIncorporationLocality};
    for (Asn1Oid m : idList) {
      conf(ids, m, RANGE_1_128, StringControl.PrintableOrUtf8);
    }

    // name
    conf(ids, AttributeOIDs.name, RANGE_NAME, StringControl.PrintableOrUtf8);

    // nameOfBirth
    conf(ids, AttributeOIDs.nameAtBirth, RANGE_1_64, StringControl.PrintableOrUtf8);

    // organizationName
    conf(ids, AttributeOIDs.organization, RANGE_1_64, StringControl.PrintableOrUtf8);

    // organizationIdentifier
    conf(ids, AttributeOIDs.organizationIdentifier, RANGE_1_64, StringControl.PrintableOrUtf8);

    // organizationalUnitName
    conf(ids, AttributeOIDs.organizationalUnit, RANGE_1_64, StringControl.PrintableOrUtf8);

    // placeOfBirth
    conf(ids, AttributeOIDs.placeOfBirth, RANGE_1_128, StringControl.PrintableOrUtf8);

    // postalAddress
    conf(ids, AttributeOIDs.postalAddress, RANGE_POSTAL_ADDRESS, null);

    // postalCode
    conf(ids, AttributeOIDs.postalCode, RANGE_POSTAL_CODE, StringControl.PrintableOrUtf8);

    // pseudonym
    conf(ids, AttributeOIDs.pseudonym, RANGE_1_64, StringControl.PrintableOrUtf8);

    // distinguishedNameQualifier
    conf(ids, AttributeOIDs.dnQualifier, RANGE_1_64, StringControl.Printable);

    // serialNumber
    conf(ids, AttributeOIDs.serialNumber, RANGE_1_64, StringControl.Printable);

    // stateOrProvinceName, jurisdictionOfIncorporationStateOrProvinceName
    idList = new Asn1Oid[] {AttributeOIDs.state, AttributeOIDs.jurIncorporationState};
    for (Asn1Oid m : idList) {
      conf(ids, m, RANGE_1_128, StringControl.PrintableOrUtf8);
    }

    // streetAddress
    conf(ids, AttributeOIDs.street, RANGE_1_128, StringControl.PrintableOrUtf8);

    // surName
    conf(ids, AttributeOIDs.surname, RANGE_1_64, StringControl.PrintableOrUtf8);

    // title
    conf(ids, AttributeOIDs.title, RANGE_1_64, StringControl.PrintableOrUtf8);

    // telefonNumber
    conf(ids, AttributeOIDs.telephoneNumber, null, StringControl.PrintableOrUtf8);

    // unstructedAddress
    conf(ids, AttributeOIDs.unstructuredAddress, null, StringControl.PrintableOrUtf8);

    // unstructedName
    conf(ids, AttributeOIDs.unstructuredName, null, StringControl.PrintableOrUtf8);

    // CSA Matter specification
    Asn1Oid[] oids = new Asn1Oid[] {
        MatterOIDs.matter_node_id,
        MatterOIDs.matter_firmware_signing_id,
        MatterOIDs.matter_icac_id,
        MatterOIDs.matter_rcac_id,
        MatterOIDs.matter_fabric_id,
        MatterOIDs.matter_vvs_id };
    for (Asn1Oid oid : oids) {
      conf(ids, oid, RANGE_16_16, StringControl.Utf8);
      PATTERNS.put(oid, TextValidator.UPPER_HEX);
    }

    conf(ids, MatterOIDs.matter_noc_cat, RANGE_8_8, StringControl.Utf8);
    PATTERNS.put(MatterOIDs.matter_noc_cat, TextValidator.UPPER_HEX);

    conf(ids, MatterOIDs.matter_oid_vid, RANGE_4_4, StringControl.PrintableOrUtf8);
    PATTERNS.put(MatterOIDs.matter_oid_vid, TextValidator.UPPER_HEX);

    conf(ids, MatterOIDs.matter_oid_pid, RANGE_4_4, StringControl.PrintableOrUtf8);
    PATTERNS.put(MatterOIDs.matter_oid_pid, TextValidator.UPPER_HEX);
  }

  private SubjectDnSpec() {
  }

  private static void conf(
      Set<Asn1Oid> types, Asn1Oid type,
      Range range, StringControl stringControl) {
    types.add(type);
    if (range != null) {
      RANGES.put(type, range);
    }

    if (stringControl != null) {
      STRING_CONTROLS.put(type, stringControl);
    }
  }

  public static void fixRdnControl(RdnControl control) {
    Asn1Oid type = Args.notNull(control, "control").type();

    // pattern
    if (control.pattern() == null && PATTERNS.containsKey(type)) {
      control.setPattern(PATTERNS.get(type));
    }

    // length ranges
    Range specRange = RANGES.get(type);
    if (specRange != null) {
      Range range = control.stringLengthRange();
      if (range == null) {
        control.setStringLengthRange(specRange);
      } else {
        range.setRange(Math.max(specRange.min(), range.min()),
            Math.min(specRange.max(), range.max()));
      }
    }

    StringControl strCtrl = STRING_CONTROLS.get(type);
    if (strCtrl != null) {
      StringType stringType = control.stringType();
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

  public static List<Asn1Oid> getForwardDNs() {
    return FORWARD_DNS;
  }

  public static boolean isValidCountryAreaCode(String code) {
    Args.notBlank(code, "code");
    return COUNTRY_AREA_CODES.isEmpty() || COUNTRY_AREA_CODES.contains(code.toUpperCase());
  }

  private static BufferedReader getReader(String propKey, String fallbackResource) {
    String confFile = System.getProperty(propKey);
    if (StringUtil.isNotBlank(confFile)) {
      LOG.info("read from file {}", confFile);
      try {
        return Files.newBufferedReader(Paths.get(confFile));
      } catch (IOException ex) {
        throw new IllegalStateException("could not access non-existing file " + confFile);
      }
    } else {
      InputStream confStream = Optional.ofNullable(
          SubjectDnSpec.class.getResourceAsStream(fallbackResource))
          .orElseThrow(() -> new IllegalStateException(
              "could not access non-existing resource " + fallbackResource));
      LOG.info("read from resource {}", fallbackResource);
      return new BufferedReader(new InputStreamReader(confStream, StandardCharsets.UTF_8));
    }
  } // method getReader

}
