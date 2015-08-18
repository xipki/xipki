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

package org.xipki.security.api;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.xipki.common.util.StringUtil;

/**
 * @author Lijun Liao
 */

public class ObjectIdentifiers
{
    /**
     * registered PEN for xipki.org: 45522
     */
    private static final ASN1ObjectIdentifier id_pen = new ASN1ObjectIdentifier("1.3.6.2.4.1");
    private static final ASN1ObjectIdentifier id_xipki = id_pen.branch("45522");

    private static final ASN1ObjectIdentifier id_xipki_ext = id_xipki.branch("1");
    public static final ASN1ObjectIdentifier id_xipki_ext_crlCertset            = id_xipki_ext.branch("1");
    public static final ASN1ObjectIdentifier id_xipki_ext_cmRequestExtensions   = id_xipki_ext.branch("2");
    public static final ASN1ObjectIdentifier id_xipki_ext_authorizationTemplate = id_xipki_ext.branch("3");

    private static final ASN1ObjectIdentifier id_xipki_cm = id_xipki.branch("2");
    public static final ASN1ObjectIdentifier id_xipki_cm_cmpGenmsg              = id_xipki_cm.branch("1");

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
    public static final ASN1ObjectIdentifier DN_LDAP_UID = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1");

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
    public static final ASN1ObjectIdentifier id_extension_restriction = new ASN1ObjectIdentifier("1.3.36.8.3.8");
    public static final ASN1ObjectIdentifier id_extension_additionalInformation = new ASN1ObjectIdentifier("1.3.36.8.3.15");
    public static final ASN1ObjectIdentifier id_extension_validityModel = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.5");

    public static final ASN1ObjectIdentifier id_extension_admission = new ASN1ObjectIdentifier("1.3.36.8.3.3");

    private static final ASN1ObjectIdentifier id_ad = id_pkix.branch("48");
    public static final ASN1ObjectIdentifier id_ad_timeStamping = id_ad.branch("3");
    public static final ASN1ObjectIdentifier id_ad_caRepository = id_ad.branch("5");

    private static final ASN1ObjectIdentifier id_qcs = id_pkix.branch("11");
    public static final ASN1ObjectIdentifier id_qcs_pkixQCSyntax_v1 = id_qcs.branch("1");
    public static final ASN1ObjectIdentifier id_qcs_pkixQCSyntax_v2 = id_qcs.branch("2");
    private static final ASN1ObjectIdentifier id_etsi_qcs = new ASN1ObjectIdentifier("0.4.0.1862.1");
    public static final ASN1ObjectIdentifier id_etsi_qcs_QcCompliance = id_etsi_qcs.branch("1");
    public static final ASN1ObjectIdentifier id_etsi_qcs_QcLimitValue = id_etsi_qcs.branch("2");
    public static final ASN1ObjectIdentifier id_etsi_qcs_QcRetentionPeriod = id_etsi_qcs.branch("3");
    public static final ASN1ObjectIdentifier id_etsi_qcs_QcSSCD = id_etsi_qcs.branch("4");

    private static final List<ASN1ObjectIdentifier> forwardDNs;
    private static final List<ASN1ObjectIdentifier> backwardDNs;
    private static final Map<ASN1ObjectIdentifier, String> oidNameMap;

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
        _forwardDNs.add(DN_LDAP_UID);
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

        oidNameMap = new HashMap<>();

        oidNameMap.put(DN_DATE_OF_BIRTH, "dateOfBirth");
        oidNameMap.put(DN_PLACE_OF_BIRTH, "placeOfBirth");
        oidNameMap.put(DN_GENDER, "gender");
        oidNameMap.put(DN_COUNTRY_OF_CITIZENSHIP, "countryOfCitizenship");
        oidNameMap.put(DN_COUNTRY_OF_RESIDENCE, "countryOfResidence");
        oidNameMap.put(DN_NAME_AT_BIRTH, "nameAtBirth");

        oidNameMap.put(id_xipki_ext_crlCertset, "xipki-crlCertset");
        oidNameMap.put(id_xipki_ext_cmRequestExtensions, "xipki-cmpRequestExtensions");
        oidNameMap.put(id_xipki_ext_authorizationTemplate, "xipki-authorizationTemplate");

        oidNameMap.put(id_kp_clientAuth, "kp-clientAuth");
        oidNameMap.put(id_kp_codeSigning, "kp-codeSigning");
        oidNameMap.put(id_kp_emailProtection, "kp-emailProtection");
        oidNameMap.put(id_kp_ipsecEndSystem, "kp-ipsecEndSystem");
        oidNameMap.put(id_kp_ipsecTunnel, "kp-ipsecTunnel");
        oidNameMap.put(id_kp_ipsecUser, "kp-ipsecUser");
        oidNameMap.put(id_kp_ocsp, "kp-ocsp");
        oidNameMap.put(id_kp_OCSPSigning, "kp-OCSPSigning");
        oidNameMap.put(id_kp_serverAuth, "kp-serverAuth");
        oidNameMap.put(id_kp_timeStamping, "kp-timeStamping");
        oidNameMap.put(id_pkix_ocsp_extendedRevoke, "pkix-ocsp-extendedRevoke");
        oidNameMap.put(id_pkix_ocsp_prefSigAlgs, "pkix-ocsp-prefSigAlgs");
        oidNameMap.put(id_tsl_kp_tslSigning, "tsl-kp-tslSigning");
        oidNameMap.put(id_extension_pkix_ocsp_nocheck, "pkix-ocsp-nocheck");
        oidNameMap.put(id_extension_restriction, "restriction");
        oidNameMap.put(id_extension_additionalInformation, "additionalInformation");
        oidNameMap.put(id_extension_admission, "admission");
        oidNameMap.put(id_extension_validityModel, "validityModel");

        oidNameMap.put(anyExtendedKeyUsage, "anyExtendedKeyUsage");
        oidNameMap.put(id_ad_caRepository, "ad-caRepository");
        oidNameMap.put(id_ad_timeStamping, "ad-timeStamping");
        oidNameMap.put(Extension.auditIdentity, "auditIdentity");
        oidNameMap.put(Extension.authorityInfoAccess, "authorityInfoAccess");
        oidNameMap.put(Extension.authorityKeyIdentifier, "authorityKeyIdentifier");
        oidNameMap.put(Extension.basicConstraints, "basicConstraints");
        oidNameMap.put(Extension.biometricInfo, "biometricInfo");
        oidNameMap.put(Extension.certificateIssuer, "certificateIssuer");
        oidNameMap.put(Extension.certificatePolicies, "certificatePolicies");
        oidNameMap.put(Extension.cRLDistributionPoints, "cRLDistributionPoints");
        oidNameMap.put(Extension.cRLNumber, "cRLNumber");
        oidNameMap.put(Extension.deltaCRLIndicator, "deltaCRLIndicator");
        oidNameMap.put(Extension.extendedKeyUsage, "extendedKeyUsage");
        oidNameMap.put(Extension.freshestCRL, "freshestCRL");
        oidNameMap.put(Extension.inhibitAnyPolicy, "inhibitAnyPolicy");
        oidNameMap.put(Extension.instructionCode, "instructionCode");
        oidNameMap.put(Extension.invalidityDate, "invalidityDate");
        oidNameMap.put(Extension.issuerAlternativeName, "issuerAlternativeName");
        oidNameMap.put(Extension.issuingDistributionPoint, "issuingDistributionPoint");
        oidNameMap.put(Extension.keyUsage, "keyUsage");
        oidNameMap.put(Extension.logoType, "logoType");
        oidNameMap.put(Extension.nameConstraints, "nameConstraints");
        oidNameMap.put(Extension.noRevAvail, "noRevAvail");
        oidNameMap.put(Extension.policyConstraints, "policyConstraints");
        oidNameMap.put(Extension.policyMappings, "policyMappings");
        oidNameMap.put(Extension.privateKeyUsagePeriod, "privateKeyUsagePeriod");
        oidNameMap.put(Extension.qCStatements, "qCStatements");
        oidNameMap.put(Extension.reasonCode, "reasonCode");
        oidNameMap.put(Extension.subjectAlternativeName, "subjectAlternativeName");
        oidNameMap.put(Extension.subjectDirectoryAttributes, "subjectDirectoryAttributes");
        oidNameMap.put(Extension.subjectInfoAccess, "subjectInfoAccess");
        oidNameMap.put(Extension.subjectKeyIdentifier, "subjectKeyIdentifier");
        oidNameMap.put(Extension.targetInformation, "targetInformation");

        oidNameMap.put(id_qcs_pkixQCSyntax_v1, "qcs-pkixQCSyntax-v2");
        oidNameMap.put(id_qcs_pkixQCSyntax_v2, "qcs-pkixQCSyntax-v2");
        oidNameMap.put(id_etsi_qcs_QcCompliance, "etsi-qcs-QcCompliance");
        oidNameMap.put(id_etsi_qcs_QcLimitValue, "etsi-qcs-QcLimitValue");
        oidNameMap.put(id_etsi_qcs_QcRetentionPeriod, "etsi-qcs-QcRetentionPeriod");
        oidNameMap.put(id_etsi_qcs_QcSSCD, "etsi-qcs-QcSSCD");
    }

    public static String oidToDisplayName(
            final ASN1ObjectIdentifier type)
    {
        String name = getName(type);
        return type.getId() + (name == null ? "" : " (" + name + ")");
    }

    public static String getName(
            final ASN1ObjectIdentifier type)
    {
        String name = oidNameMap.get(type);

        if(StringUtil.isBlank(name))
        {
            try
            {
                name = RFC4519Style.INSTANCE.oidToDisplayName(type);
            }catch(IllegalArgumentException e)
            {
            }
        }
        return name;
    }

    public static ASN1ObjectIdentifier nameToOID(
            final String name)
    {
        for(ASN1ObjectIdentifier oid : oidNameMap.keySet())
        {
            if(oidNameMap.get(oid).equalsIgnoreCase(name))
            {
                return oid;
            }
        }

        try
        {
            return RFC4519Style.INSTANCE.attrNameToOID(name);
        }catch(IllegalArgumentException e)
        {
            return null;
        }
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
