// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.xipki.util.StringUtil;

import java.util.HashMap;
import java.util.Map;

import static org.xipki.util.Args.notNull;

/**
 * Collection of OBJECT IDENFIFIERS.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class ObjectIdentifiers {

  /**
   * Extended key usages.
   */
  private static final ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");

  /**
   * registered PEN for xipki.org: 45522
   */
  public static final ASN1ObjectIdentifier id_pen = new ASN1ObjectIdentifier("1.3.6.1.4.1");

  private static final ASN1ObjectIdentifier id_xipki = id_pen.branch("45522");

  private static final ASN1ObjectIdentifier id_microsoft = id_pen.branch("311");

  // CCC: Car Connectivity Consortium
  private static final ASN1ObjectIdentifier id_ccc = id_pen.branch("41577");

  public static final class CMP {
    public static final ASN1ObjectIdentifier id_it_certProfile = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.21");
  }

  public static final class CMC {
    public static final ASN1ObjectIdentifier id_cmc_changeSubjectName = CMCObjectIdentifiers.id_cmc.branch("36");
  }

  public static final class Xipki {

    // id_xipki_ext := id_xipki ext{1}
    // deprecated: id_xipk_ext_crlCertset := id_xipki_ext {1}
    // deprecated id_xipki_ext_cmpRequestExtensions := id_xipki_ext {2}
    // deprecated id_xipki_ext_authorizationTemplate := id_xipki_ext {3}

    private static final ASN1ObjectIdentifier id_xipki_cmp = id_xipki.branch("2");

    public static final ASN1ObjectIdentifier id_xipki_cmp_cmpGenmsg = id_xipki_cmp.branch("1");

    // deprecated id_xipki_cmp_cacerts = id_xipki_cmp {2};

    private static final ASN1ObjectIdentifier id_xipki_alg = id_xipki.branch("3");

    public static final ASN1ObjectIdentifier id_alg_dhPop_x25519 = id_xipki_alg.branch("1");

    public static final ASN1ObjectIdentifier id_alg_dhPop_x448 = id_xipki_alg.branch("2");

  } // class Xipki

  public static class BaseRequirements { // base requirements
    public static final ASN1ObjectIdentifier id_domain_validated = new ASN1ObjectIdentifier("2.23.140.1.2.1");
    public static final ASN1ObjectIdentifier id_organization_validated = new ASN1ObjectIdentifier("2.23.140.1.2.2");
    public static final ASN1ObjectIdentifier id_individual_validated = new ASN1ObjectIdentifier("2.23.140.1.2.3");
  }

  public static class DN {
    /**
     * country code - StringType(SIZE(2)).
     */
    public static final ASN1ObjectIdentifier C = new ASN1ObjectIdentifier("2.5.4.6");

    /**
     * organization - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier O = new ASN1ObjectIdentifier("2.5.4.10");

    /**
     * organizationIdentifier - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier organizationIdentifier = new ASN1ObjectIdentifier("2.5.4.97");

    /**
     * organizational unit name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier OU = new ASN1ObjectIdentifier("2.5.4.11");

    /**
     * Title.
     */
    public static final ASN1ObjectIdentifier T = new ASN1ObjectIdentifier("2.5.4.12");

    /**
     * common name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier CN = new ASN1ObjectIdentifier("2.5.4.3");

    /**
     * device serial number name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier SN = new ASN1ObjectIdentifier("2.5.4.5");

    /**
     * street - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier street = new ASN1ObjectIdentifier("2.5.4.9");

    /**
     * device serial number name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier serialNumber = SN;

    /**
     * locality name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier L = new ASN1ObjectIdentifier("2.5.4.7");

    public static final ASN1ObjectIdentifier localityName = L;

    /**
     * state, or province name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier ST = new ASN1ObjectIdentifier("2.5.4.8");

    /**
     * Naming attributes of type X520name.
     */
    public static final ASN1ObjectIdentifier surname = new ASN1ObjectIdentifier("2.5.4.4");

    public static final ASN1ObjectIdentifier givenName = new ASN1ObjectIdentifier("2.5.4.42");

    public static final ASN1ObjectIdentifier initials = new ASN1ObjectIdentifier("2.5.4.43");

    public static final ASN1ObjectIdentifier generation = new ASN1ObjectIdentifier("2.5.4.44");

    public static final ASN1ObjectIdentifier generationQualifier = generation;

    public static final ASN1ObjectIdentifier uniqueIdentifier = new ASN1ObjectIdentifier("2.5.4.45");

    /**
     * businessCategory - DirectoryString(SIZE(1..128)
     */
    public static final ASN1ObjectIdentifier businessCategory = new ASN1ObjectIdentifier("2.5.4.15");

    /**
     * postalCode - DirectoryString(SIZE(1..40)
     */
    public static final ASN1ObjectIdentifier postalCode = new ASN1ObjectIdentifier("2.5.4.17");

    /**
     * dnQualifier - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier dnQualifier = new ASN1ObjectIdentifier("2.5.4.46");

    /**
     * RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier pseudonym = new ASN1ObjectIdentifier("2.5.4.65");

    /**
     * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z.
     */
    public static final ASN1ObjectIdentifier dateOfBirth = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1");

    /**
     * RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
     */
    public static final ASN1ObjectIdentifier placeOfBirth = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2");

    /**
     * RFC 3039 Gender - PrintableString (SIZE(1))-- "M", "F", "m" or "f".
     */
    public static final ASN1ObjectIdentifier gender = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3");

    /**
     * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2))-- ISO 3166 codes only.
     */
    public static final ASN1ObjectIdentifier countryOfCitizenship = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4");

    /**
     * RFC 3039 CountryOfResidence - PrintableString (SIZE (2))-- ISO 3166 codes only.
     */
    public static final ASN1ObjectIdentifier countryOfResidence = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.5");

    /**
     * ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier nameAtBirth = new ASN1ObjectIdentifier("1.3.36.8.3.14");

    /**
     * RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
     * DirectoryString(SIZE(1..30))
     */
    public static final ASN1ObjectIdentifier postalAddress = new ASN1ObjectIdentifier("2.5.4.16");

    /**
     * RFC 2256 dmdName.
     */
    public static final ASN1ObjectIdentifier dmdName = new ASN1ObjectIdentifier("2.5.4.54");

    /**
     * id-at-telephoneNumber.
     */
    public static final ASN1ObjectIdentifier telephoneNumber = X509ObjectIdentifiers.id_at_telephoneNumber;

    /**
     * id-at-name.
     */
    public static final ASN1ObjectIdentifier name = X509ObjectIdentifiers.id_at_name;

    /**
     * Email address (RSA PKCS#9 extension) - IA5String.
     *
     * <p>Note: if you're trying to be ultra orthodox, don't use this! It shouldn't be in here.
     */
    public static final ASN1ObjectIdentifier emailAddress = PKCSObjectIdentifiers.pkcs_9_at_emailAddress;

    /**
     * more from PKCS#9.
     */
    public static final ASN1ObjectIdentifier unstructuredName = PKCSObjectIdentifiers.pkcs_9_at_unstructuredName;

    public static final ASN1ObjectIdentifier unstructuredAddress = PKCSObjectIdentifiers.pkcs_9_at_unstructuredAddress;

    /**
     * email address in certificates.
     */
    public static final ASN1ObjectIdentifier E = emailAddress;

    /*
    * others...
    */
    public static final ASN1ObjectIdentifier DC = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.25");

    /**
     * LDAP User id.
     */
    public static final ASN1ObjectIdentifier userid = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1");

    /**
     * LDAP User id.
     */
    public static final ASN1ObjectIdentifier UID = userid;

    /**
     * NIF, Tax ID number, for individuals (Spain).
     */
    public static final ASN1ObjectIdentifier NIF = id_pen.branch("18838.1.1");

    /**
     * CIF, Tax ID code, for companies (Spain).
     */
    public static final ASN1ObjectIdentifier CIF = id_pen.branch("4710.1.3.2");

    /**
     * jurisdictionOfIncorporationLocalityName.
     */
    public static final ASN1ObjectIdentifier jurisdictionOfIncorporationLocalityName =
        id_microsoft.branch("60.2.1.1");

    /**
     * jurisdictionOfIncorporationStateOrProvinceName.
     */
    public static final ASN1ObjectIdentifier jurisdictionOfIncorporationStateOrProvinceName =
        id_microsoft.branch("60.2.1.2");

    /**
     * jurisdictionOfIncorporationCountryName.
     */
    public static final ASN1ObjectIdentifier jurisdictionOfIncorporationCountryName =
        id_microsoft.branch("60.2.1.3");
  }

  // extended key usage
  public static final class XKU {

    public static final ASN1ObjectIdentifier id_kp_anyExtendedKeyUsage = Extension.extendedKeyUsage.branch("0");

    private static final ASN1ObjectIdentifier id_kp = id_pkix.branch("3");

    /**
     * TLS WWW client authentication
     * Key usage bits that may be consistent: digitalSignature and/or keyAgreement.
     */
    public static final ASN1ObjectIdentifier id_kp_clientAuth = id_kp.branch("2");

    /**
     * Signing of downloadable executable code
     * Key usage bits that may be consistent: digitalSignature.
     */
    public static final ASN1ObjectIdentifier id_kp_codeSigning = id_kp.branch("3");

    /**
     * CSN 369791 TLS client.
     */
    public static final ASN1ObjectIdentifier id_kp_csn369791TlsClient =
        new ASN1ObjectIdentifier("1.2.203.7064.1.1.369791.1");

    /**
     * CSN 369791 TLS server.
     */
    public static final ASN1ObjectIdentifier id_kp_csn369791TlsServer =
        new ASN1ObjectIdentifier("1.2.203.7064.1.1.369791.2");

    /**
     * EAP over LAN (EAPOL).
     */
    public static final ASN1ObjectIdentifier id_kp_eapOverLan = id_kp.branch("14");

    /**
     * EAP over PPP.
     */
    public static final ASN1ObjectIdentifier id_kp_eapOverPpp = id_kp.branch("13");

    /**
     * Email protection
     * Key usage bits that may be consistent: digitalSignature, nonRepudiation, and/or
     * (keyEncipherment or keyAgreement).
     */
    public static final ASN1ObjectIdentifier id_kp_emailProtection = id_kp.branch("4");

    /**
     * ETSI TSL Signing.
     */
    public static final ASN1ObjectIdentifier id_kp_etsiTslSigning = new ASN1ObjectIdentifier("0.4.0.2231.3.0");

    /**
     * ICAO Master List Signing.
     */
    public static final ASN1ObjectIdentifier id_kp_icaoMasterListSigning = new ASN1ObjectIdentifier("2.23.136.1.1.3");

    /**
     * Internet Key Exchange for IPsec.
     */
    public static final ASN1ObjectIdentifier id_kp_ikeForIpsec = id_kp.branch("17");

    /**
     * Intel AMT management.
     */
    public static final ASN1ObjectIdentifier id_kp_intelAmtManagement =
        new ASN1ObjectIdentifier("2.16.840.1.113741.1.2.3");

    /**
     * This purpose has been included in a predecessor draft of RFC 3280
     * and therefore continue to be listed by this implementation.
     *
     * <p>IP security end system.
     */
    public static final ASN1ObjectIdentifier id_kp_ipsecEndSystem = id_kp.branch("5");

    /**
     * This purpose has been included in a predecessor draft of RFC 3280
     * and therefore continue to be listed by this implementation.
     *
     * <p>IP security tunnel termination.
     */
    public static final ASN1ObjectIdentifier id_kp_ipsecTunnel = id_kp.branch("6");

    /**
     * This purpose has been included in a predecessor draft of RFC 3280
     * and therefore continue to be listed by this implementation.
     *
     * <p>IP security user.
     */
    public static final ASN1ObjectIdentifier id_kp_ipsecUser = id_kp.branch("7");

    /**
     * Kerberos Client Authentication.
     */
    public static final ASN1ObjectIdentifier id_kp_kerberosClientAuthentication =
        new ASN1ObjectIdentifier("1.3.6.1.5.2.3.4");

    /**
     * Kerberos Key Distribution Center.
     */
    public static final ASN1ObjectIdentifier id_kp_kerberosKdc = new ASN1ObjectIdentifier("1.3.6.1.5.2.3.5");

    /**
     * Microsoft Commercial Code Signing.
     */
    public static final ASN1ObjectIdentifier id_kp_microsoftCommercialCodeSigning =
        id_microsoft.branch("2.1.22");

    /**
     * Microsoft Document Signing.
     */
    public static final ASN1ObjectIdentifier id_kp_microsoftDocumentSigning = id_microsoft.branch("10.3.12");

    /**
     * Microsoft Encrypted File System (EFS).
     */
    public static final ASN1ObjectIdentifier id_kp_microsoftEfs = id_microsoft.branch("10.3.4");

    /**
     * Microsoft EFS Recovery.
     */
    public static final ASN1ObjectIdentifier id_kp_microsoftEfsRecovery = id_microsoft.branch("10.3.4.1");

    /**
     * Microsoft Individual Code Signing.
     */
    public static final ASN1ObjectIdentifier id_kp_microsoftIndividualCodeSigning =
        id_microsoft.branch("2.1.21");

    /**
     * Microsoft Smart Card Logon.
     */
    public static final ASN1ObjectIdentifier id_kp_microsoftSmartCardLogon = id_microsoft.branch("20.2.2");

    /**
     * Signing OCSP responses
     * Key usage bits that may be consistent: digitalSignature and/or nonRepudiation.
     */
    public static final ASN1ObjectIdentifier id_kp_ocspSigning = id_kp.branch("9");

    /**
     * PIV Card Authentication.
     */
    public static final ASN1ObjectIdentifier id_kp_pivCardAuthentication =
        new ASN1ObjectIdentifier("2.16.840.1.101.3.6.8");

    /**
     * PDF Signing.
     */
    public static final ASN1ObjectIdentifier id_kp_pdfSigning = new ASN1ObjectIdentifier("1.2.840.113583.1.1.5");

    /**
     * SCVP Client.
     */
    public static final ASN1ObjectIdentifier id_kp_scvpClient = id_kp.branch("16");

    /**
     * SCVP Server.
     */
    public static final ASN1ObjectIdentifier id_kp_scvpServer = id_kp.branch("15");

    /**
     * TLS WWW server authentication
     * Key usage bits that may be consistent: digitalSignature, keyEncipherment or keyAgreement.
     */
    public static final ASN1ObjectIdentifier id_kp_serverAuth = id_kp.branch("1");

    /**
     * SIP Domain.
     */
    public static final ASN1ObjectIdentifier id_kp_sipDomain = id_kp.branch("20");

    /**
     * SSH Client.
     */
    public static final ASN1ObjectIdentifier id_kp_sshClient = id_kp.branch("21");

    /**
     * SSH Server.
     */
    public static final ASN1ObjectIdentifier id_kp_sshServer = id_kp.branch("22");

    /**
     * Binding the hash of an object to a time
     * Key usage bits that may be consistent: digitalSignature and/or nonRepudiation.
     */
    public static final ASN1ObjectIdentifier id_kp_timeStamping = id_kp.branch("8");

    private static final ASN1ObjectIdentifier id_appleExtendedKeyUsage =
        new ASN1ObjectIdentifier("1.2.840.113635.100.4");

    public static final ASN1ObjectIdentifier id_kp_appleSafariExtensionSigning =
        id_appleExtendedKeyUsage.branch("8");

    public static final ASN1ObjectIdentifier id_kp_macInstallerPackageSigning =
        id_appleExtendedKeyUsage.branch("9");

    public static final ASN1ObjectIdentifier id_kp_macAppStoreInstallerPackageSigning =
        id_appleExtendedKeyUsage.branch("10");

    // Certificate Transparency (RFC 6962)
    public static final ASN1ObjectIdentifier id_kp_certificateTransparency =
        new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.4.4");
  }

  public static final class Extn {

    // OCSP
    public static final ASN1ObjectIdentifier id_pkix_ocsp_prefSigAlgs =
        OCSPObjectIdentifiers.id_pkix_ocsp.branch("8");

    public static final ASN1ObjectIdentifier id_pkix_ocsp_extendedRevoke =
        OCSPObjectIdentifiers.id_pkix_ocsp.branch("9");

    public static final ASN1ObjectIdentifier id_extension_pkix_ocsp_nocheck = id_pkix.branch("48.1.5");

    public static final ASN1ObjectIdentifier id_extension_restriction = new ASN1ObjectIdentifier("1.3.36.8.3.8");

    public static final ASN1ObjectIdentifier id_extension_additionalInformation =
        new ASN1ObjectIdentifier("1.3.36.8.3.15");

    public static final ASN1ObjectIdentifier id_extension_validityModel =
        new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.5");

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

    public static final ASN1ObjectIdentifier id_etsi_qcs_QcPDS = id_etsi_qcs.branch("5");

    // RFC 7633: X.509v3 Transport Layer Security (TLS) Feature Extension
    private static final ASN1ObjectIdentifier id_pe = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1");

    public static final ASN1ObjectIdentifier id_pe_tlsfeature = id_pe.branch("24");

    // RFC 4262: SMIMECapatibilities
    public static final ASN1ObjectIdentifier id_smimeCapabilities = new ASN1ObjectIdentifier("1.2.840.113549.1.9.15");

    private static final ASN1ObjectIdentifier id_GMT_0015 = new ASN1ObjectIdentifier("1.2.156.10260.4.1");

    // GMT 0015-2012 SM2-Based Certificate
    public static final ASN1ObjectIdentifier id_GMT_0015_IdentityCode = id_GMT_0015.branch("1");

    // GMT 0015-2012 SM2-Based Certificate
    public static final ASN1ObjectIdentifier id_GMT_0015_InsuranceNumber = id_GMT_0015.branch("2");

    // GMT 0015-2012 SM2-Based Certificate
    public static final ASN1ObjectIdentifier id_GMT_0015_ICRegistrationNumber = id_GMT_0015.branch("3");

    // GMT 0015-2012 SM2-Based Certificate
    public static final ASN1ObjectIdentifier id_GMT_0015_OrganizationCode = id_GMT_0015.branch("4");

    // GMT 0015-2012 SM2-Based Certificate
    public static final ASN1ObjectIdentifier id_GMT_0015_TaxationNumber = id_GMT_0015.branch("5");

    // Certificate Transparency (RFC 6962)
    public static final ASN1ObjectIdentifier id_precertificate = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3");

    // Certificate Transparency (RFC 6962)
    public static final ASN1ObjectIdentifier id_SCTs = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2");

    // CCC: Car Connectivity Consortium
    public static final ASN1ObjectIdentifier id_ccc_extn = id_ccc.branch("5");
    public static final ASN1ObjectIdentifier id_ccc_Vehicle_Cert_K = id_ccc_extn.branch("1");
    public static final ASN1ObjectIdentifier id_ccc_External_CA_Cert_F = id_ccc_extn.branch("2");
    public static final ASN1ObjectIdentifier id_ccc_Internal_CA_Cert_E = id_ccc_extn.branch("3");
    public static final ASN1ObjectIdentifier id_ccc_Endpoint_Cert_H = id_ccc_extn.branch("4");
    public static final ASN1ObjectIdentifier id_ccc_VehicleOEM_Enc_Cert = id_ccc_extn.branch("5");
    public static final ASN1ObjectIdentifier id_ccc_VehicleOEM_Sig_Cert = id_ccc_extn.branch("6");
    public static final ASN1ObjectIdentifier id_ccc_Device_Enc_Cert = id_ccc_extn.branch("7");
    public static final ASN1ObjectIdentifier id_ccc_Vehicle_Intermediate_Cert = id_ccc_extn.branch("8");
    public static final ASN1ObjectIdentifier id_ccc_VehicleOEM_CA_Cert_J = id_ccc_extn.branch("9");
    public static final ASN1ObjectIdentifier id_ccc_VehicleOEM_CA_Cert_M = id_ccc_extn.branch("10");
  }

  /*
  public static final ASN1ObjectIdentifier id_aes128_cbc_in_ecies = id_secg_scheme.branch("20.0");

  public static final ASN1ObjectIdentifier id_ecies_specifiedParameters =
      id_secg_scheme.branch("8");

  public static final ASN1ObjectIdentifier id_hmac_full_ecies = id_secg_scheme.branch("22");

  public static final ASN1ObjectIdentifier id_iso18033_kdf2 =
      new ASN1ObjectIdentifier("1.0.18033.2.5.2");
   */
  public static final class Secg {
    private static final ASN1ObjectIdentifier id_secg_scheme = new ASN1ObjectIdentifier("1.3.132.1");

    public static final ASN1ObjectIdentifier id_aes128_cbc_in_ecies = id_secg_scheme.branch("20.0");

    public static final ASN1ObjectIdentifier id_ecies_specifiedParameters = id_secg_scheme.branch("8");

    public static final ASN1ObjectIdentifier id_hmac_full_ecies = id_secg_scheme.branch("22");
  }

  public static final class Misc {
    public static final ASN1ObjectIdentifier id_iso18033_kdf2 = new ASN1ObjectIdentifier("1.0.18033.2.5.2");
  }

  private static class OidNameMap {
    private static final Map<ASN1ObjectIdentifier, String> oidNameMap;

    static {
      oidNameMap = new HashMap<>();

      oidNameMap.put(DN.countryOfCitizenship, "countryOfCitizenship");
      oidNameMap.put(DN.countryOfResidence, "countryOfResidence");
      oidNameMap.put(DN.dateOfBirth, "dateOfBirth");
      oidNameMap.put(DN.dmdName, "dmdName");
      oidNameMap.put(DN.emailAddress, "emailAddress");
      oidNameMap.put(DN.gender, "gender");
      oidNameMap.put(DN.nameAtBirth, "nameAtBirth");
      oidNameMap.put(DN.organizationIdentifier, "organizationIdentifier");
      oidNameMap.put(DN.placeOfBirth, "placeOfBirth");
      oidNameMap.put(DN.pseudonym, "pseudonym");
      oidNameMap.put(DN.unstructuredName, "unstructuredName");
      oidNameMap.put(DN.unstructuredAddress, "unstructuredAddress");
      oidNameMap.put(DN.NIF, "NIF, Tax ID number, for individuals (Spain)");
      oidNameMap.put(DN.CIF, "CIF, Tax ID code, for companies (Spain)");
      oidNameMap.put(DN.jurisdictionOfIncorporationCountryName, "jurisdictionOfIncorporationCountryName");
      oidNameMap.put(DN.jurisdictionOfIncorporationStateOrProvinceName,
          "jurisdictionOfIncorporationStateOrProvinceName");
      oidNameMap.put(DN.jurisdictionOfIncorporationLocalityName, "jurisdictionOfIncorporationLocalityName");

      oidNameMap.put(Extn.id_pkix_ocsp_extendedRevoke, "pkix-ocsp-extendedRevoke");
      oidNameMap.put(Extn.id_pkix_ocsp_prefSigAlgs, "pkix-ocsp-prefSigAlgs");
      oidNameMap.put(Extn.id_extension_pkix_ocsp_nocheck, "pkix-ocsp-nocheck");
      oidNameMap.put(Extn.id_extension_restriction, "restriction");
      oidNameMap.put(Extn.id_extension_additionalInformation, "additionalInformation");
      oidNameMap.put(Extn.id_extension_admission, "admission");
      oidNameMap.put(Extn.id_extension_validityModel, "validityModel");
      oidNameMap.put(Extn.id_ad_caRepository, "ad-caRepository");
      oidNameMap.put(Extn.id_ad_timeStamping, "ad-timeStamping");

      oidNameMap.put(Extn.id_qcs_pkixQCSyntax_v1, "qcs-pkixQCSyntax-v2");
      oidNameMap.put(Extn.id_qcs_pkixQCSyntax_v2, "qcs-pkixQCSyntax-v2");
      oidNameMap.put(Extn.id_etsi_qcs_QcCompliance, "etsi-qcs-QcCompliance");
      oidNameMap.put(Extn.id_etsi_qcs_QcLimitValue, "etsi-qcs-QcLimitValue");
      oidNameMap.put(Extn.id_etsi_qcs_QcRetentionPeriod, "etsi-qcs-QcRetentionPeriod");
      oidNameMap.put(Extn.id_etsi_qcs_QcSSCD, "etsi-qcs-QcSSCD");
      oidNameMap.put(Extn.id_pe_tlsfeature, "tlsFeature");
      oidNameMap.put(Extn.id_smimeCapabilities, "SMIMECapatibilities");
      oidNameMap.put(Extn.id_GMT_0015_ICRegistrationNumber, "GMT 0015 ICRegistrationNumber");
      oidNameMap.put(Extn.id_GMT_0015_IdentityCode, "GMT 0015 IdentityCode");
      oidNameMap.put(Extn.id_GMT_0015_InsuranceNumber, "GMT 0015 InsuranceNumber");
      oidNameMap.put(Extn.id_GMT_0015_OrganizationCode, "GMT 0015 OrganizationCode");
      oidNameMap.put(Extn.id_GMT_0015_TaxationNumber, "GMT 0015 TaxationNumber");
      oidNameMap.put(Extn.id_precertificate, "CT Precertificate Indication");
      oidNameMap.put(Extn.id_SCTs, "CT Precertificate SCTs");
      // CCC
      oidNameMap.put(Extn.id_ccc_Vehicle_Cert_K, "CCC Vehicle Certificate [K]");
      oidNameMap.put(Extn.id_ccc_External_CA_Cert_F, "CCC External CA Certificate [F]");
      oidNameMap.put(Extn.id_ccc_Internal_CA_Cert_E, "CCC External CA Certificate [E]");
      oidNameMap.put(Extn.id_ccc_Endpoint_Cert_H, "Endpoint Certificate [H]");
      oidNameMap.put(Extn.id_ccc_VehicleOEM_Enc_Cert, "CCC VehicleOEM.Enc.Cert");
      oidNameMap.put(Extn.id_ccc_VehicleOEM_Sig_Cert, "CCC VehicleOEM.Sig.Cert");
      oidNameMap.put(Extn.id_ccc_Device_Enc_Cert, "CCC Device.Enc.Cert");
      oidNameMap.put(Extn.id_ccc_Vehicle_Intermediate_Cert, "CCC Vehicle Intermediate Certificate");
      oidNameMap.put(Extn.id_ccc_VehicleOEM_CA_Cert_J, "CCC Vehicle OEM CA Certificate [J]");
      oidNameMap.put(Extn.id_ccc_VehicleOEM_CA_Cert_M, "CCC Vehicle OEM CA Certificate [M]");

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

      oidNameMap.put(Secg.id_aes128_cbc_in_ecies, "aes128-cbc-in-ecies");
      oidNameMap.put(Secg.id_ecies_specifiedParameters, "ecies-specifiedParameters");
      oidNameMap.put(Secg.id_hmac_full_ecies, "hmac-full-ecies");

      oidNameMap.put(Misc.id_iso18033_kdf2, "kdf2");

      // Extended Key Usage
      oidNameMap.put(XKU.id_kp_anyExtendedKeyUsage, "Any ExtendedKeyUsage");
      oidNameMap.put(XKU.id_kp_clientAuth, "TLS WWW client authentication");
      oidNameMap.put(XKU.id_kp_codeSigning, "Code signing");
      oidNameMap.put(XKU.id_kp_csn369791TlsClient, "CSN 369791 TLS client");
      oidNameMap.put(XKU.id_kp_csn369791TlsServer, "CSN 369791 TLS server");
      oidNameMap.put(XKU.id_kp_eapOverLan, "EAP over LAN (EAPOL)");
      oidNameMap.put(XKU.id_kp_eapOverPpp, "EAP over PPP");
      oidNameMap.put(XKU.id_kp_emailProtection, "Email protection");
      oidNameMap.put(XKU.id_kp_etsiTslSigning, "ETSI TSL Signing");
      oidNameMap.put(XKU.id_kp_icaoMasterListSigning, "ICAO Master List Signing");
      oidNameMap.put(XKU.id_kp_ikeForIpsec, "Internet Key Exchange for IPsec");
      oidNameMap.put(XKU.id_kp_intelAmtManagement, "Intel AMT management");
      oidNameMap.put(XKU.id_kp_ipsecEndSystem, "IP security end system");
      oidNameMap.put(XKU.id_kp_ipsecTunnel, "IP security tunnel termination");
      oidNameMap.put(XKU.id_kp_ipsecUser, "IP security user");
      oidNameMap.put(XKU.id_kp_kerberosClientAuthentication, "Kerberos Client Authentication");
      oidNameMap.put(XKU.id_kp_kerberosKdc, "Kerberos Key Distribution Center");
      oidNameMap.put(XKU.id_kp_microsoftCommercialCodeSigning, "Microsoft Commercial Code Signing");
      oidNameMap.put(XKU.id_kp_microsoftDocumentSigning, "Microsoft Document Signing");
      oidNameMap.put(XKU.id_kp_microsoftEfs, "Microsoft Encrypted File System");
      oidNameMap.put(XKU.id_kp_microsoftEfsRecovery, "Microsoft EFS Recovery");
      oidNameMap.put(XKU.id_kp_microsoftIndividualCodeSigning, "Microsoft Individual Code Signing");
      oidNameMap.put(XKU.id_kp_microsoftSmartCardLogon, "Microsoft Smart Card Logon");
      oidNameMap.put(XKU.id_kp_ocspSigning, "Signing OCSP responses");
      oidNameMap.put(XKU.id_kp_pivCardAuthentication, "PIV Card Authentication");
      oidNameMap.put(XKU.id_kp_pdfSigning, "PDF Signing");
      oidNameMap.put(XKU.id_kp_scvpClient, "SCVP Client");
      oidNameMap.put(XKU.id_kp_scvpServer, "SCVP Server");
      oidNameMap.put(XKU.id_kp_serverAuth, "TLS WWW server authentication");
      oidNameMap.put(XKU.id_kp_sipDomain, "SIP Domain");
      oidNameMap.put(XKU.id_kp_sshClient, "SSH Client");
      oidNameMap.put(XKU.id_kp_sshServer, "SSH Server");
      oidNameMap.put(XKU.id_kp_timeStamping, "TimeStamping");

      oidNameMap.put(XKU.id_kp_appleSafariExtensionSigning, "Apple Safari Extension Signing");
      oidNameMap.put(XKU.id_kp_macInstallerPackageSigning, "Apple Mac Installer Package Signing");
      oidNameMap.put(XKU.id_kp_macAppStoreInstallerPackageSigning, "Apple Mac AppStore Installer Package Signing");

      oidNameMap.put(EdECConstants.id_ED25519, EdECConstants.ED25519);
      oidNameMap.put(EdECConstants.id_ED448, EdECConstants.ED448);
      oidNameMap.put(EdECConstants.id_X25519, EdECConstants.X25519);
      oidNameMap.put(EdECConstants.id_X448, EdECConstants.X448);
    }
  }

  private ObjectIdentifiers() {
  }

  public static String oidToDisplayName(ASN1ObjectIdentifier type) {
    notNull(type, "type");
    String name = getName(type);
    return (name == null) ? type.getId() : type.getId() + " (" + name + ")";
  }

  public static String getName(ASN1ObjectIdentifier type) {
    notNull(type, "type");
    String name = OidNameMap.oidNameMap.get(type);

    if (StringUtil.isBlank(name)) {
      try {
        name = BCStyle.INSTANCE.oidToDisplayName(type);
      } catch (IllegalArgumentException ex) {
      }
    }
    return name;
  }

  public static ASN1ObjectIdentifier nameToOid(String name) {
    notNull(name, "name");
    for (ASN1ObjectIdentifier oid : OidNameMap.oidNameMap.keySet()) {
      if (OidNameMap.oidNameMap.get(oid).equalsIgnoreCase(name)) {
        return oid;
      }
    }

    try {
      return BCStyle.INSTANCE.attrNameToOID(name);
    } catch (IllegalArgumentException ex) {
      return null;
    }
  }

}
