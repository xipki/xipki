/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.api.profile.x509;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.pki.ca.api.CertprofileException;
import org.xipki.pki.ca.api.profile.Range;
import org.xipki.pki.ca.api.profile.RdnControl;
import org.xipki.pki.ca.api.profile.StringType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
public class SubjectDnSpec {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectDnSpec.class);

    public static final Pattern PATTERN_DATE_OF_BIRTH =
            Pattern.compile("^(19|20)\\d\\d(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])000000Z");

    /**
     * ranges.
     */
    private static final Range RANGE_64 = new Range(1, 64);

    private static final Range RANGE_128 = new Range(1, 128);

    private static final Range RANGE_POSTAL_CODE = new Range(1, 40);

    private static final Range RANGE_COUNTRY_NAME = new Range(2, 2);

    private static final Range RANGE_POSTAL_ADDRESS = new Range(0, 30);

    private static final Range RANGE_GENDER = new Range(1, 1);

    private static final Range RANGE_DATE_OF_BIRTH = new Range(15, 15);

    // according to specification should be 32768, 256 is specified by xipki.
    private static final Range RANGE_NAME = new Range(1, 256);

    // patterns
    private static final Pattern PATTERN_GENDER = Pattern.compile("M|m|F|f");

    private static final Pattern PATTERN_COUNTRY = Pattern.compile("[A-Za-z]{2}");

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

    private static final List<ASN1ObjectIdentifier> forwardDNs;

    private static final List<ASN1ObjectIdentifier> backwardDNs;

    private static final Set<String> countryAreaCodes = new HashSet<>();

    static {
        // ----- RDN order -----
        BufferedReader reader = getReader("org.xipki.pki.ca.rdnorder.cfg", "/conf/rdnorder.cfg");
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
            throw new RuntimeException("could not load RDN order: " + ex.getMessage(), ex);
        } finally {
            try {
                reader.close();
            } catch (IOException ex) {
                // CHECKSTYLE:SKIP
            }
        }

        forwardDNs = Collections.unmodifiableList(tmpForwardDNs);
        if (LOG.isInfoEnabled()) {
            StringBuilder sb = new StringBuilder(500);
            sb.append("forward RDNs: ");
            for (ASN1ObjectIdentifier oid : forwardDNs) {
                sb.append(oid.getId()).append(", ");
            }
            if (!forwardDNs.isEmpty()) {
                sb.delete(sb.length() - 2, sb.length());
            }
            LOG.info(sb.toString());
        }

        List<ASN1ObjectIdentifier> tmpBackwardDNs = new ArrayList<>(25);
        int size = tmpForwardDNs.size();
        for (int i = size - 1; i >= 0; i--) {
            tmpBackwardDNs.add(tmpForwardDNs.get(i));
        }

        backwardDNs = Collections.unmodifiableList(tmpBackwardDNs);
        if (LOG.isInfoEnabled()) {
            StringBuilder sb = new StringBuilder(500);
            sb.append("backward RDNs: ");
            for (ASN1ObjectIdentifier oid : backwardDNs) {
                sb.append(oid.getId()).append(", ");
            }
            if (!backwardDNs.isEmpty()) {
                sb.delete(sb.length() - 2, sb.length());
            }
            LOG.info(sb.toString());
        }

        // ----- country/area code -----
        reader = getReader("org.xipki.pki.ca.areacode.cfg", "/conf/areacode.cfg");
        try {
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                StringTokenizer st = new StringTokenizer(line, " \t");
                final int n = st.countTokens();
                // 1. country/area name
                // 2. ISO ALPHA-2 code
                // 3. ISO ALPHA-3 code
                // 4. ISO numeric code
                if (n < 4) {
                    LOG.warn("invalid country/area line {}", line);
                    continue;
                }

                final int alpha2CodeIndex = n - 3;
                for (int i = 0; i < alpha2CodeIndex; i++) {
                    st.nextToken();
                }

                String areaCode = st.nextToken();
                countryAreaCodes.add(areaCode.toUpperCase());
            }

            if (LOG.isInfoEnabled()) {
                List<String> list = new ArrayList<>(countryAreaCodes);
                Collections.sort(list);
                LOG.info("area/country codes: {}", list);
            }
        } catch (Exception ex) {
            throw new RuntimeException("could not load area code: " + ex.getMessage(), ex);
        } finally {
            try {
                reader.close();
            } catch (IOException ex) {
                // CHECKSTYLE:SKIP
            }
        }

        LOG.info("country/area codess: {}", countryAreaCodes);

        // ----- Type, Length -----
        ASN1ObjectIdentifier id;

        Set<ASN1ObjectIdentifier> ids = new HashSet<>();

        // businessCategory
        id = ObjectIdentifiers.DN_BUSINESS_CATEGORY;
        ids.add(id);
        RANGES.put(id, RANGE_128);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // countryName
        id = ObjectIdentifiers.DN_C;
        ids.add(id);
        RANGES.put(id, RANGE_COUNTRY_NAME);
        STRING_TYPE_SET.put(id, PRINTABLE_STRING_ONLY);
        DFLT_STRING_TYPES.put(id, StringType.printableString);

        // commonName
        id = ObjectIdentifiers.DN_CN;
        ids.add(id);
        RANGES.put(id, RANGE_64);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // countryOfCitizenship
        id = ObjectIdentifiers.DN_COUNTRY_OF_CITIZENSHIP;
        ids.add(id);
        RANGES.put(id, RANGE_COUNTRY_NAME);
        PATTERNS.put(id, PATTERN_COUNTRY);
        STRING_TYPE_SET.put(id, PRINTABLE_STRING_ONLY);
        DFLT_STRING_TYPES.put(id, StringType.printableString);

        // countryOfResidence
        id = ObjectIdentifiers.DN_COUNTRY_OF_RESIDENCE;
        ids.add(id);
        RANGES.put(id, RANGE_COUNTRY_NAME);
        PATTERNS.put(id, PATTERN_COUNTRY);
        STRING_TYPE_SET.put(id, PRINTABLE_STRING_ONLY);
        DFLT_STRING_TYPES.put(id, StringType.printableString);

        // DATE_OF_BIRTH
        id = ObjectIdentifiers.DN_DATE_OF_BIRTH;
        ids.add(id);
        RANGES.put(id, RANGE_DATE_OF_BIRTH);
        PATTERNS.put(id, PATTERN_DATE_OF_BIRTH);

        // domainComponent
        id = ObjectIdentifiers.DN_DC;
        ids.add(id);
        STRING_TYPE_SET.put(id, IA5_STRING_ONLY);
        DFLT_STRING_TYPES.put(id, StringType.ia5String);

        // RFC 2256 dmdName
        id = ObjectIdentifiers.DN_DMD_NAME;
        ids.add(id);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // gender
        id = ObjectIdentifiers.DN_GENDER;
        ids.add(id);
        PATTERNS.put(id, PATTERN_GENDER);
        RANGES.put(id, RANGE_GENDER);
        STRING_TYPE_SET.put(id, PRINTABLE_STRING_ONLY);
        DFLT_STRING_TYPES.put(id, StringType.printableString);

        // generation qualifier
        id = ObjectIdentifiers.DN_GENERATION_QUALIFIER;
        ids.add(id);
        RANGES.put(id, RANGE_64);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // givenName
        id = ObjectIdentifiers.DN_GIVENNAME;
        ids.add(id);
        RANGES.put(id, RANGE_64);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // initials
        id = ObjectIdentifiers.DN_INITIALS;
        ids.add(id);
        RANGES.put(id, RANGE_64);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // LDAP user ID
        id = ObjectIdentifiers.DN_LDAP_UID;
        ids.add(id);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // localityName
        id = ObjectIdentifiers.DN_LOCALITYNAME;
        ids.add(id);
        RANGES.put(id, RANGE_128);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // name
        id = ObjectIdentifiers.DN_NAME;
        ids.add(id);
        RANGES.put(id, RANGE_NAME);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // nameOfBirth
        id = ObjectIdentifiers.DN_NAME_AT_BIRTH;
        ids.add(id);
        RANGES.put(id, RANGE_64);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // organizationName
        id = ObjectIdentifiers.DN_O;
        ids.add(id);
        RANGES.put(id, RANGE_64);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // organizationIdentifier
        id = ObjectIdentifiers.DN_organizationIdentifier;
        ids.add(id);
        RANGES.put(id, RANGE_64);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // organizationalUnitName
        id = ObjectIdentifiers.DN_OU;
        ids.add(id);
        RANGES.put(id, RANGE_64);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // placeOfBirth
        id = ObjectIdentifiers.DN_PLACE_OF_BIRTH;
        ids.add(id);
        RANGES.put(id, RANGE_128);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // postalAddress
        id = ObjectIdentifiers.DN_POSTAL_ADDRESS;
        ids.add(id);
        RANGES.put(id, RANGE_POSTAL_ADDRESS);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // postalCode
        id = ObjectIdentifiers.DN_POSTAL_CODE;
        ids.add(id);
        RANGES.put(id, RANGE_POSTAL_CODE);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // pseudonym
        id = ObjectIdentifiers.DN_PSEUDONYM;
        ids.add(id);
        RANGES.put(id, RANGE_64);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // distinguishedNameQualifier
        id = ObjectIdentifiers.DN_QUALIFIER;
        ids.add(id);
        RANGES.put(id, RANGE_64);
        STRING_TYPE_SET.put(id, PRINTABLE_STRING_ONLY);
        DFLT_STRING_TYPES.put(id, StringType.printableString);

        // serialNumber
        id = ObjectIdentifiers.DN_SERIALNUMBER;
        ids.add(id);
        RANGES.put(id, RANGE_64);
        STRING_TYPE_SET.put(id, PRINTABLE_STRING_ONLY);
        DFLT_STRING_TYPES.put(id, StringType.printableString);

        // stateOrProvinceName
        id = ObjectIdentifiers.DN_ST;
        ids.add(id);
        RANGES.put(id, RANGE_128);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // streetAddress
        id = ObjectIdentifiers.DN_STREET;
        ids.add(id);
        RANGES.put(id, RANGE_128);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // surName
        id = ObjectIdentifiers.DN_SURNAME;
        ids.add(id);
        RANGES.put(id, RANGE_64);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // title
        id = ObjectIdentifiers.DN_T;
        ids.add(id);
        RANGES.put(id, RANGE_64);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // telefonNumber
        id = ObjectIdentifiers.DN_TELEPHONE_NUMBER;
        ids.add(id);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // unique Identifier
        id = ObjectIdentifiers.DN_UNIQUE_IDENTIFIER;
        ids.add(id);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // unstructedAddress
        id = ObjectIdentifiers.DN_UnstructuredAddress;
        ids.add(id);
        STRING_TYPE_SET.put(id, DIRECTORY_STRINGS);
        DFLT_STRING_TYPES.put(id, StringType.utf8String);

        // unstructedName
        id = ObjectIdentifiers.DN_UnstructuredName;
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
                control.setPatterns(Arrays.asList(pattern));
            }
            CONTROLS.put(type, control);
        }
    }

    private SubjectDnSpec() {
    }

    public static Range getStringLengthRange(
            final ASN1ObjectIdentifier rdnType) {
        ParamUtil.requireNonNull("rdnType", rdnType);
        return RANGES.get(rdnType);
    }

    public static Pattern getPattern(
            final ASN1ObjectIdentifier rdnType) {
        ParamUtil.requireNonNull("rdnType", rdnType);
        return PATTERNS.get(rdnType);
    }

    public static StringType getStringType(
            final ASN1ObjectIdentifier rdnType) {
        ParamUtil.requireNonNull("rdnType", rdnType);
        return DFLT_STRING_TYPES.get(rdnType);
    }

    public static RdnControl getRdnControl(
            final ASN1ObjectIdentifier rdnType) {
        ParamUtil.requireNonNull("rdnType", rdnType);
        RdnControl control = CONTROLS.get(rdnType);
        if (control == null) {
            control = new RdnControl(rdnType,
                    0, // minOccurs
                    9 // maxOccurs
                    );
            control.setStringType(StringType.utf8String);
        }
        return control;
    } // static

    public static void fixRdnControl(
            final RdnControl control)
    throws CertprofileException {
        ParamUtil.requireNonNull("control", control);

        ASN1ObjectIdentifier type = control.getType();
        StringType stringType = control.getStringType();
        if (stringType != null) {
            if (STRING_TYPE_SET.containsKey(type)
                    && !STRING_TYPE_SET.get(type).contains(stringType)) {
                throw new CertprofileException(
                    String.format("%s is not allowed %s", stringType.name(), type.getId()));
            }
        } else {
            StringType specStrType = DFLT_STRING_TYPES.get(type);
            if (specStrType != null) {
                control.setStringType(specStrType);
            }
        }

        if (control.getPatterns() == null && PATTERNS.containsKey(type)) {
            control.setPatterns(Arrays.asList(PATTERNS.get(type)));
        }

        Range specRange = RANGES.get(type);
        Range isRange = (specRange == null)
                ? null
                : control.getStringLengthRange();
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
        return forwardDNs;
    }

    public static List<ASN1ObjectIdentifier> getBackwardDNs() {
        return backwardDNs;
    }

    public static boolean isValidCountryAreaCode(String code) {
        ParamUtil.requireNonBlank("code", code);
        return countryAreaCodes.isEmpty()
                ? true
                : countryAreaCodes.contains(code.toUpperCase());
    }

    private static BufferedReader getReader(
            String propKey,
            String fallbackResource) {
        String confFile = System.getProperty(propKey);
        if (StringUtil.isNotBlank(confFile)) {
            LOG.info("read from file " + confFile);
            try {
                return new BufferedReader(new FileReader(confFile));
            } catch (FileNotFoundException ex) {
                throw new RuntimeException("could not access non-existing file " + confFile);
            }
        } else {
            InputStream confStream = SubjectDnSpec.class.getResourceAsStream(fallbackResource);
            if (confStream == null) {
                throw new RuntimeException("could not access non-existing resource "
                        + fallbackResource);
            }
            LOG.info("read from resource " + fallbackResource);
            return new BufferedReader(new InputStreamReader(confStream));
        }
    }

}
