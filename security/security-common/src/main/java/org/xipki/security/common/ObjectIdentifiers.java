/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.security.common;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 * @author Lijun Liao
 */

public class ObjectIdentifiers
{
    /**
     * country code - StringType(SIZE(2))
     */
    public static final ASN1ObjectIdentifier DN_C = new ASN1ObjectIdentifier("2.5.4.6");

    /**
     * organization - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier DN_O = new ASN1ObjectIdentifier("2.5.4.10");

    /**
     * organizational unit name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier DN_OU = new ASN1ObjectIdentifier("2.5.4.11");

    /**
     * Title
     */
    public static final ASN1ObjectIdentifier DN_T = new ASN1ObjectIdentifier("2.5.4.12");

    /**
     * common name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier DN_CN = new ASN1ObjectIdentifier("2.5.4.3");

    /**
     * device serial number name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier DN_SN = new ASN1ObjectIdentifier("2.5.4.5");

    /**
     * street - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier DN_STREET = new ASN1ObjectIdentifier("2.5.4.9");

    /**
     * device serial number name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier DN_SERIALNUMBER = DN_SN;

    /**
     * locality name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier DN_L = new ASN1ObjectIdentifier("2.5.4.7");

    /**
     * state, or province name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier DN_ST = new ASN1ObjectIdentifier("2.5.4.8");

    /**
     * Naming attributes of type X520name
     */
    public static final ASN1ObjectIdentifier DN_SURNAME = new ASN1ObjectIdentifier("2.5.4.4");
    public static final ASN1ObjectIdentifier DN_GIVENNAME = new ASN1ObjectIdentifier("2.5.4.42");
    public static final ASN1ObjectIdentifier DN_INITIALS = new ASN1ObjectIdentifier("2.5.4.43");
    public static final ASN1ObjectIdentifier DN_GENERATION = new ASN1ObjectIdentifier("2.5.4.44");
    public static final ASN1ObjectIdentifier DN_UNIQUE_IDENTIFIER = new ASN1ObjectIdentifier("2.5.4.45");

    /**
     * businessCategory - DirectoryString(SIZE(1..128)
     */
    public static final ASN1ObjectIdentifier DN_BUSINESS_CATEGORY = new ASN1ObjectIdentifier(
        "2.5.4.15");

    /**
     * postalCode - DirectoryString(SIZE(1..40)
     */
    public static final ASN1ObjectIdentifier DN_POSTAL_CODE = new ASN1ObjectIdentifier(
        "2.5.4.17");

    /**
     * dnQualifier - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier DN_QUALIFIER = new ASN1ObjectIdentifier(
        "2.5.4.46");

    /**
     * RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier DN_PSEUDONYM = new ASN1ObjectIdentifier(
        "2.5.4.65");

    /**
     * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z
     */
    public static final ASN1ObjectIdentifier DN_DATE_OF_BIRTH = new ASN1ObjectIdentifier(
        "1.3.6.1.5.5.7.9.1");

    /**
     * RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
     */
    public static final ASN1ObjectIdentifier DN_PLACE_OF_BIRTH = new ASN1ObjectIdentifier(
        "1.3.6.1.5.5.7.9.2");

    /**
     * RFC 3039 Gender - PrintableString (SIZE(1)) -- "M", "F", "m" or "f"
     */
    public static final ASN1ObjectIdentifier DN_GENDER = new ASN1ObjectIdentifier(
        "1.3.6.1.5.5.7.9.3");

    /**
     * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2)) -- ISO 3166
     * codes only
     */
    public static final ASN1ObjectIdentifier DN_COUNTRY_OF_CITIZENSHIP = new ASN1ObjectIdentifier(
        "1.3.6.1.5.5.7.9.4");

    /**
     * RFC 3039 CountryOfResidence - PrintableString (SIZE (2)) -- ISO 3166
     * codes only
     */
    public static final ASN1ObjectIdentifier DN_COUNTRY_OF_RESIDENCE = new ASN1ObjectIdentifier(
        "1.3.6.1.5.5.7.9.5");

    /**
     * ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier DN_NAME_AT_BIRTH = new ASN1ObjectIdentifier("1.3.36.8.3.14");

    /**
     * RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
     * DirectoryString(SIZE(1..30))
     */
    public static final ASN1ObjectIdentifier DN_POSTAL_ADDRESS = new ASN1ObjectIdentifier("2.5.4.16");

    /**
     * RFC 2256 dmdName
     */
    public static final ASN1ObjectIdentifier DN_DMD_NAME = new ASN1ObjectIdentifier("2.5.4.54");

    /**
     * id-at-telephoneNumber
     */
    public static final ASN1ObjectIdentifier DN_TELEPHONE_NUMBER = X509ObjectIdentifiers.id_at_telephoneNumber;

    /**
     * id-at-name
     */
    public static final ASN1ObjectIdentifier DN_NAME = X509ObjectIdentifiers.id_at_name;

    /**
     * Email address (RSA PKCS#9 extension) - IA5String.
     * <p>Note: if you're trying to be ultra orthodox, don't use this! It shouldn't be in here.
     */
    public static final ASN1ObjectIdentifier DN_EmailAddress = PKCSObjectIdentifiers.pkcs_9_at_emailAddress;

    /**
     * more from PKCS#9
     */
    public static final ASN1ObjectIdentifier DN_UnstructuredName = PKCSObjectIdentifiers.pkcs_9_at_unstructuredName;
    public static final ASN1ObjectIdentifier DN_UnstructuredAddress = PKCSObjectIdentifiers.pkcs_9_at_unstructuredAddress;

    /**
     * email address in certificates
     */
    public static final ASN1ObjectIdentifier DN_E = DN_EmailAddress;

    /*
    * others...
    */
    public static final ASN1ObjectIdentifier DN_DC = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.25");

    /**
     * LDAP User id.
     */
    public static final ASN1ObjectIdentifier DN_UID = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1");

    /**
     * Extended key usages
     */
    private static final ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");
    private static final ASN1ObjectIdentifier id_kp                  = id_pkix.branch("3");

    /**
     * TLS WWW server authentication
     * Key usage bits that may be consistent: digitalSignature,
     * keyEncipherment or keyAgreement
     */
    public static final ASN1ObjectIdentifier id_kp_serverAuth        = id_kp.branch("1");

    /**
     * TLS WWW client authentication
     * Key usage bits that may be consistent: digitalSignature
     * and/or keyAgreement
     */
    public static final ASN1ObjectIdentifier id_kp_clientAuth        = id_kp.branch("2");

    /**
     * Signing of downloadable executable code
     * Key usage bits that may be consistent: digitalSignature
     */
    public static final ASN1ObjectIdentifier id_kp_codeSigning        = id_kp.branch("3");

    /**
     * Email protection
     * Key usage bits that may be consistent: digitalSignature,
     * nonRepudiation, and/or (keyEncipherment or keyAgreement)
     */
    public static final ASN1ObjectIdentifier id_kp_emailProtection        = id_kp.branch("4");

    /**
     * Binding the hash of an object to a time
     * Key usage bits that may be consistent: digitalSignature
     * and/or nonRepudiation
     */
    public static final ASN1ObjectIdentifier id_kp_timeStamping        = id_kp.branch("8");

    /**
     * Signing OCSP responses
     * Key usage bits that may be consistent: digitalSignature
     * and/or nonRepudiation
     */
    public static final ASN1ObjectIdentifier id_kp_OCSPSigning        = id_kp.branch("9");

    /*
     * The following purposes have been included in a predecessor draft of RFC 3280
     * and therefore continue to be registrated by this implementation:
     */

    /**
     * IP security end system
     */
    public static final ASN1ObjectIdentifier id_kp_ipsecEndSystem  = id_kp.branch("5");

    /**
     * IP security tunnel termination
     */
    public static final ASN1ObjectIdentifier id_kp_ipsecTunnel  = id_kp.branch("6");

    /**
     * IP security user
     */
    public static final ASN1ObjectIdentifier id_kp_ipsecUser  = id_kp.branch("7");

    // OCSP
    public static final ASN1ObjectIdentifier id_pkix_ocsp_prefSigAlgs = OCSPObjectIdentifiers.id_pkix_ocsp.branch("8");
    public static final ASN1ObjectIdentifier id_pkix_ocsp_extendedRevoke = OCSPObjectIdentifiers.id_pkix_ocsp.branch("9");

    public static final ASN1ObjectIdentifier id_tsl_kp_tslSigning    = new ASN1ObjectIdentifier("0.4.0.2231.3.0");

    public static final ASN1ObjectIdentifier id_kp_ocsp              = id_pkix.branch("1.48.1");
    public static final ASN1ObjectIdentifier id_extension_pkix_ocsp_nocheck = id_pkix.branch("48.1.5");

    public static String oidToDisplayName(ASN1ObjectIdentifier type)
    {
        String displayName = RFC4519Style.INSTANCE.oidToDisplayName(type);
        return type.getId() + (displayName == null ? "" : " (" + displayName + ")");
    }

}
