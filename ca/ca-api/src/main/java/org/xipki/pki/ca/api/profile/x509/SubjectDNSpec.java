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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.pki.ca.api.CertprofileException;
import org.xipki.pki.ca.api.profile.RDNControl;
import org.xipki.pki.ca.api.profile.Range;
import org.xipki.pki.ca.api.profile.StringType;
import org.xipki.security.api.ObjectIdentifiers;

/**
 * @author Lijun Liao
 */

public class SubjectDNSpec {

    /**
     * ranges
     */
    private static final Range r_64 = new Range(1, 64);

    private static final Range r_128 = new Range(1, 128);

    private static final Range r_postalCode = new Range(1, 40);

    private static final Range r_countryName = new Range(2, 2);

    private static final Range r_postalAddress = new Range(0, 30);

    private static final Range r_gender = new Range(1, 1);

    private static final Range r_dateOfBirth = new Range(15, 15);

    // according to specification should be 32768, 256 is specified by xipki.
    private static final Range r_name = new Range(1, 256);

    // patterns
    private static final Pattern p_gender = Pattern.compile("M|m|F|f");

    private static final Pattern p_country = Pattern.compile("[A-Za-z]{2}");

    public static final Pattern p_dateOfBirth =
            Pattern.compile("^(19|20)\\d\\d(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])000000Z");

    // stringTypes
    private static final Set<StringType> directoryStrings = new HashSet<>(
            Arrays.asList(StringType.bmpString, StringType.printableString,
                    StringType.teletexString, StringType.utf8String));

    private static final Set<StringType> printableStringOnly = new HashSet<>(
            Arrays.asList(StringType.printableString));

    private static final Set<StringType> ia5StringOnly = new HashSet<>(
            Arrays.asList(StringType.ia5String));

    private static final Map<ASN1ObjectIdentifier, StringType> defaultStringTypes = new HashMap<>();

    private static final Map<ASN1ObjectIdentifier, Range> ranges = new HashMap<>();

    private static final Map<ASN1ObjectIdentifier, Pattern> patterns = new HashMap<>();

    private static final Map<ASN1ObjectIdentifier, RDNControl> controls = new HashMap<>();

    private static final Map<ASN1ObjectIdentifier, Set<StringType>> stringTypeSets =
            new HashMap<>();

    static {
        ASN1ObjectIdentifier id;

        Set<ASN1ObjectIdentifier> ids = new HashSet<>();

        // businessCategory
        id = ObjectIdentifiers.DN_BUSINESS_CATEGORY;
        ids.add(id);
        ranges.put(id, r_128);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // countryName
        id = ObjectIdentifiers.DN_C;
        ids.add(id);
        ranges.put(id, r_countryName);
        stringTypeSets.put(id, printableStringOnly);
        defaultStringTypes.put(id, StringType.printableString);

        // commonName
        id = ObjectIdentifiers.DN_CN;
        ids.add(id);
        ranges.put(id, r_64);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // countryOfCitizenship
        id = ObjectIdentifiers.DN_COUNTRY_OF_CITIZENSHIP;
        ids.add(id);
        ranges.put(id, r_countryName);
        patterns.put(id, p_country);
        stringTypeSets.put(id, printableStringOnly);
        defaultStringTypes.put(id, StringType.printableString);

        // countryOfResidence
        id = ObjectIdentifiers.DN_COUNTRY_OF_RESIDENCE;
        ids.add(id);
        ranges.put(id, r_countryName);
        patterns.put(id, p_country);
        stringTypeSets.put(id, printableStringOnly);
        defaultStringTypes.put(id, StringType.printableString);

        // dateOfBirth
        id = ObjectIdentifiers.DN_DATE_OF_BIRTH;
        ids.add(id);
        ranges.put(id, r_dateOfBirth);
        patterns.put(id, p_dateOfBirth);

        // domainComponent
        id = ObjectIdentifiers.DN_DC;
        ids.add(id);
        stringTypeSets.put(id, ia5StringOnly);
        defaultStringTypes.put(id, StringType.ia5String);

        // RFC 2256 dmdName
        id = ObjectIdentifiers.DN_DMD_NAME;
        ids.add(id);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // gender
        id = ObjectIdentifiers.DN_GENDER;
        ids.add(id);
        patterns.put(id, p_gender);
        ranges.put(id, r_gender);
        stringTypeSets.put(id, printableStringOnly);
        defaultStringTypes.put(id, StringType.printableString);

        // generation qualifier
        id = ObjectIdentifiers.DN_GENERATION_QUALIFIER;
        ids.add(id);
        ranges.put(id, r_64);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // givenName
        id = ObjectIdentifiers.DN_GIVENNAME;
        ids.add(id);
        ranges.put(id, r_64);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // initials
        id = ObjectIdentifiers.DN_INITIALS;
        ids.add(id);
        ranges.put(id, r_64);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // LDAP user ID
        id = ObjectIdentifiers.DN_LDAP_UID;
        ids.add(id);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // localityName
        id = ObjectIdentifiers.DN_LOCALITYNAME;
        ids.add(id);
        ranges.put(id, r_128);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // name
        id = ObjectIdentifiers.DN_NAME;
        ids.add(id);
        ranges.put(id, r_name);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // nameOfBirth
        id = ObjectIdentifiers.DN_NAME_AT_BIRTH;
        ids.add(id);
        ranges.put(id, r_64);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // organizationName
        id = ObjectIdentifiers.DN_O;
        ids.add(id);
        ranges.put(id, r_64);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // organizationalUnitName
        id = ObjectIdentifiers.DN_OU;
        ids.add(id);
        ranges.put(id, r_64);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // placeOfBirth
        id = ObjectIdentifiers.DN_PLACE_OF_BIRTH;
        ids.add(id);
        ranges.put(id, r_128);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // postalAddress
        id = ObjectIdentifiers.DN_POSTAL_ADDRESS;
        ids.add(id);
        ranges.put(id, r_postalAddress);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // postalCode
        id = ObjectIdentifiers.DN_POSTAL_CODE;
        ids.add(id);
        ranges.put(id, r_postalCode);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // pseudonym
        id = ObjectIdentifiers.DN_PSEUDONYM;
        ids.add(id);
        ranges.put(id, r_64);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // distinguishedNameQualifier
        id = ObjectIdentifiers.DN_QUALIFIER;
        ids.add(id);
        ranges.put(id, r_64);
        stringTypeSets.put(id, printableStringOnly);
        defaultStringTypes.put(id, StringType.printableString);

        // serialNumber
        id = ObjectIdentifiers.DN_SERIALNUMBER;
        ids.add(id);
        ranges.put(id, r_64);
        stringTypeSets.put(id, printableStringOnly);
        defaultStringTypes.put(id, StringType.printableString);

        // stateOrProvinceName
        id = ObjectIdentifiers.DN_ST;
        ids.add(id);
        ranges.put(id, r_128);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // streetAddress
        id = ObjectIdentifiers.DN_STREET;
        ids.add(id);
        ranges.put(id, r_128);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // surName
        id = ObjectIdentifiers.DN_SURNAME;
        ids.add(id);
        ranges.put(id, r_64);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // title
        id = ObjectIdentifiers.DN_T;
        ids.add(id);
        ranges.put(id, r_64);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // telefonNumber
        id = ObjectIdentifiers.DN_TELEPHONE_NUMBER;
        ids.add(id);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // unique Identifier
        id = ObjectIdentifiers.DN_UNIQUE_IDENTIFIER;
        ids.add(id);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // unstructedAddress
        id = ObjectIdentifiers.DN_UnstructuredAddress;
        ids.add(id);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        // unstructedName
        id = ObjectIdentifiers.DN_UnstructuredName;
        ids.add(id);
        stringTypeSets.put(id, directoryStrings);
        defaultStringTypes.put(id, StringType.utf8String);

        for (ASN1ObjectIdentifier type : ids) {
            Pattern pattern = patterns.get(type);
            StringType stringType = defaultStringTypes.get(type);
            if (stringType == null) {
                stringType = StringType.utf8String;
            }
            RDNControl control = new RDNControl(type,
                    0, // minOccurs
                    9 //maxOccurs
                    );
            control.setStringType(stringType);
            control.setStringLengthRange(ranges.get(type));
            if (pattern != null) {
                control.setPatterns(Arrays.asList(pattern));
            }
            controls.put(type, control);
        }
    }

    private SubjectDNSpec() {
    }

    public static Range getStringLengthRange(
            final ASN1ObjectIdentifier rdnType) {
        return ranges.get(rdnType);
    }

    public static Pattern getPattern(
            final ASN1ObjectIdentifier rdnType) {
        return patterns.get(rdnType);
    }

    public static StringType getStringType(
            final ASN1ObjectIdentifier rdnType) {
        return defaultStringTypes.get(rdnType);
    }

    public static RDNControl getRDNControl(
            final ASN1ObjectIdentifier rdnType) {
        RDNControl control = controls.get(rdnType);
        if (control == null) {
            control = new RDNControl(rdnType,
                    0, // minOccurs
                    9 // maxOccurs
                    );
            control.setStringType(StringType.utf8String);
        }
        return control;
    } // static

    public static void fixRDNControl(
            final RDNControl control)
    throws CertprofileException {
        ASN1ObjectIdentifier type = control.getType();

        StringType stringType = control.getStringType();
        if (stringType != null) {
            if (stringTypeSets.containsKey(type)
                    && !stringTypeSets.get(type).contains(stringType)) {
                throw new CertprofileException(
                    String.format("%s is not allowed %s", stringType.name(), type.getId()));
            }
        } else {
            StringType specStrType = defaultStringTypes.get(type);
            if (specStrType != null) {
                control.setStringType(specStrType);
            }
        }

        if (control.getPatterns() == null && patterns.containsKey(type)) {
            control.setPatterns(Arrays.asList(patterns.get(type)));
        }

        Range specRange = ranges.get(type);
        if (specRange != null) {
            Range isRange = control.getStringLengthRange();
            if (isRange == null) {
                control.setStringLengthRange(specRange);
            } else {
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
                }
            } // isRange
        } // specRange
    } // method fixRDNControl

}
