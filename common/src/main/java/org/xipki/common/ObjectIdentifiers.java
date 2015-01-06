/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.common;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.Extension;
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
    public static final ASN1ObjectIdentifier DN_LOCALITYNAME = DN_L;

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
    public static final ASN1ObjectIdentifier DN_GENERATION_QUALIFIER = DN_GENERATION;
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

    public static final ASN1ObjectIdentifier anyExtendedKeyUsage  = Extension.extendedKeyUsage.branch("0");

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

    public static final ASN1ObjectIdentifier id_extension_admission = new ASN1ObjectIdentifier("1.3.36.8.3.3");

    private static final ASN1ObjectIdentifier id_ad = id_pkix.branch("48");
    public static final ASN1ObjectIdentifier id_ad_timeStamping = id_ad.branch("3");
    public static final ASN1ObjectIdentifier id_ad_caRepository = id_ad.branch("5");

    private static final List<ASN1ObjectIdentifier> forwardDNs;
    private static final List<ASN1ObjectIdentifier> backwardDNs;

    static
    {
        List<ASN1ObjectIdentifier> _forwardDNs = new ArrayList<>(25);

        _forwardDNs.add(DN_C);
        _forwardDNs.add(DN_DC);
        _forwardDNs.add(DN_ST);
        _forwardDNs.add(DN_L);
        _forwardDNs.add(DN_O);
        _forwardDNs.add(DN_OU);
        _forwardDNs.add(DN_T);
        _forwardDNs.add(DN_SURNAME);
        _forwardDNs.add(DN_INITIALS);
        _forwardDNs.add(DN_GIVENNAME);
        _forwardDNs.add(DN_SERIALNUMBER);
        _forwardDNs.add(DN_NAME);
        _forwardDNs.add(DN_CN);
        _forwardDNs.add(DN_UID);
        _forwardDNs.add(DN_DMD_NAME);
        _forwardDNs.add(DN_EmailAddress);
        _forwardDNs.add(DN_UnstructuredName);
        _forwardDNs.add(DN_UnstructuredAddress);
        _forwardDNs.add(DN_POSTAL_CODE);
        _forwardDNs.add(DN_BUSINESS_CATEGORY);
        _forwardDNs.add(DN_POSTAL_ADDRESS);
        _forwardDNs.add(DN_TELEPHONE_NUMBER);
        _forwardDNs.add(DN_PSEUDONYM);
        _forwardDNs.add(DN_STREET);

        forwardDNs = Collections.unmodifiableList(_forwardDNs);

        List<ASN1ObjectIdentifier> _backwardDNs = new ArrayList<>(25);
        int size = _forwardDNs.size();
        for(int i = size - 1; i >= 0; i--)
        {
            _backwardDNs.add(_forwardDNs.get(i));
        }

        backwardDNs = Collections.unmodifiableList(_backwardDNs);
    }

    public static String oidToDisplayName(ASN1ObjectIdentifier type)
    {
        String name = getName(type);
        return type.getId() + (name == null ? "" : " (" + name + ")");
    }

    public static String getName(ASN1ObjectIdentifier type)
    {
        String name = RFC4519Style.INSTANCE.oidToDisplayName(type);
        if(name == null)
        {
            if(id_kp_clientAuth.equals(type))
            {
                name = "id-kp-clientAuth";
            }
            else if(id_kp_codeSigning.equals(type))
            {
                name = "id-kp-codeSigning";
            }
            else if(id_kp_emailProtection.equals(type))
            {
                name = "id-kp-emailProtection";
            }
            else if(id_kp_ipsecEndSystem.equals(type))
            {
                name = "id-kp-ipsecEndSystem";
            }
            else if(id_kp_ipsecTunnel.equals(type))
            {
                name = "id-kp-ipsecTunnel";
            }
            else if(id_kp_ipsecUser.equals(type))
            {
                name = "id-kp-ipsecUser";
            }
            else if(id_kp_ocsp.equals(type))
            {
                name = "id-kp-ocsp";
            }
            else if(id_kp_OCSPSigning.equals(type))
            {
                name = "id-kp-OCSPSigning";
            }
            else if(id_kp_serverAuth.equals(type))
            {
                name = "id-kp-serverAuth";
            }
            else if(id_kp_timeStamping.equals(type))
            {
                name = "id-kp-timeStamping";
            }
            else if(id_pkix_ocsp_extendedRevoke.equals(type))
            {
                name = "id-pkix-ocsp-extendedRevoke";
            }
            else if(id_pkix_ocsp_prefSigAlgs.equals(type))
            {
                name = "id-pkix-ocsp-prefSigAlgs";
            }
            else if(id_tsl_kp_tslSigning.equals(type))
            {
                name = "id-tsl-kp-tslSigning";
            }
            else if(id_extension_pkix_ocsp_nocheck.equals(type))
            {
                name = "id-pkix-ocsp-nocheck";
            }
            else if(id_extension_admission.equals(type))
            {
                name = "admission";
            }
            else if(anyExtendedKeyUsage.equals(type))
            {
                name = "anyExtendedKeyUsage";
            }
            else if(id_ad_caRepository.equals(type))
            {
                name = "id-ad-caRepository";
            }
            else if(id_ad_timeStamping.equals(type))
            {
                name = "id-ad-timeStamping";
            }
        }

        return name;
    }

    public static List<ASN1ObjectIdentifier> getForwardDNs()
    {
        return forwardDNs;
    }

    public static List<ASN1ObjectIdentifier> getBackwardDNs()
    {
        return backwardDNs;
    }

}
