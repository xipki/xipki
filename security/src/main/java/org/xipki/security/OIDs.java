// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.codec.Args;

import java.util.HashMap;
import java.util.Map;

/**
 * Collection of OBJECT IDENTIFIERS.
 *
 * @author Lijun Liao (xipki)
 */

public class OIDs {

  private static final Map<String, String> oidNameMap = new HashMap<>();

  private static boolean initialized = false;

  private synchronized static void init() {
    if (initialized) {
      return;
    }

    DN.country.getId();
    X509.id_ad_caIssuers.getId();
    Extn.id_ad_caRepository.getId();
    CMC.id_cmc_changeSubjectName.getId();
    Algo.AES128_GMAC.getId();
    PolicyIdentifier.id_domain_validated.getId();
    PolicyQualifierId.cps.getId();
    ACME.id_pe_acmeIdentifier.getId();
    CMP.id_it_caCerts.getId();
    CMS.data.getId();
    Curve.brainpoolP192r1.getId();
    Misc.isismtt_at_certHash.getId();
    OCSP.id_pkix_ocsp_crl.getId();
    PKCS9.pkcs9_at_challengePassword.getId();
    QCS.id_etsi_qcs_QcCClegislation.getId();
    Scep.failInfo.getId();
    Secg.id_aes128_cbc_in_ecies.getId();
    Spdm.id_spdm.getId();
    Xipki.id_alg_dhPop_x448.getId();
    XKU.id_kp_anyExtendedKeyUsage.getId();
    initialized = true;
  }

  private static ASN1ObjectIdentifier initOid(String oid, String name) {
    return initOid(new ASN1ObjectIdentifier(oid), name);
  }

  private static ASN1ObjectIdentifier initOid(
      ASN1ObjectIdentifier oid, String name) {
    String id = oid.getId();
    String mainAlias = name != null ? name.trim() : id;

    if (oidNameMap.put(id, mainAlias) != null) {
      throw new RuntimeException("duplicated oid: " + oid.getId() +
          " (alias " + mainAlias + ")");
    }

    return oid;
  }

  public static final class CMP {

    public static final ASN1ObjectIdentifier id_it_certProfile = initOid(
        "1.3.6.1.5.5.7.4.21", "it_certProfile");

    public static final ASN1ObjectIdentifier regCtrl_oldCertID = initOid(
        "1.3.6.1.5.5.7.5.1.5", "regCtrl-oldCertID");

    public static final ASN1ObjectIdentifier it_implicitConfirm = initOid(
        "1.3.6.1.5.5.7.4.13", "it-implicitConfirm");

    public static final ASN1ObjectIdentifier regInfo_utf8Pairs = initOid(
        "1.3.6.1.5.5.7.5.2.1", "regInfo-utf8Pairs");

    public static final ASN1ObjectIdentifier it_currentCRL = initOid(
        "1.3.6.1.5.5.7.4.6", "it-currentCRL");

    public static final ASN1ObjectIdentifier id_it_caCerts = initOid(
        "1.3.6.1.5.5.7.4.17", "it-caCerts");

    public static final ASN1ObjectIdentifier it_confirmWaitTime = initOid(
        "1.3.6.1.5.5.7.4.14", "it-confirmWaitTime");

  }

  public static final class CMC {

    public static final ASN1ObjectIdentifier id_cmc_changeSubjectName = initOid(
        "1.3.6.1.5.5.7.7.36", "cmc_changeSubjectName");
  }

  public static final class X509 {

    public static final ASN1ObjectIdentifier id_ad_ocsp = initOid(
        "1.3.6.1.5.5.7.48.1", "OCSP");

    public static final ASN1ObjectIdentifier id_ad_caIssuers = initOid(
        "1.3.6.1.5.5.7.48.2", "CA Issuers");

    public static final ASN1ObjectIdentifier id_ad_rpkiManifest = initOid(
        "1.3.6.1.5.5.7.48.10", "RPKI Manifest");

    public static final ASN1ObjectIdentifier id_ad_signedObject = initOid(
        "1.3.6.1.5.5.7.48.11", "Signed Object");

    public static final ASN1ObjectIdentifier id_ad_rpkiNotify = initOid(
        "1.3.6.1.5.5.7.48.13", "RPKI Notify");

    // otherName with hardwareModuleName
    public static final ASN1ObjectIdentifier id_on_hardwareModuleName = initOid(
        "1.3.6.1.5.5.7.8.4", "hardwareModuleName");

    // otherName with SmtpUTF8Mailbox
    public static final ASN1ObjectIdentifier id_on_SmtpUTF8Mailbox = initOid(
        "1.3.6.1.5.5.7.8.9", "SmtpUTF8Mailbox");
  }

  public static final class ACME {

    public static final ASN1ObjectIdentifier id_pe_acmeIdentifier = initOid(
        "1.3.6.1.5.5.7.1.31", "pe-acmeIdentifier");

  }

  public static final class Xipki {

    /**
     * registered PEN for xipki.org: 45522
     */
    private static final ASN1ObjectIdentifier id_xipki =
        new ASN1ObjectIdentifier("1.3.6.1.4.1.45522");

    // id_xipki_ext := id_xipki ext{1}
    // deprecated: id_xipk_ext_crlCertset := id_xipki_ext {1}
    // deprecated id_xipki_ext_cmpRequestExtensions := id_xipki_ext {2}
    // deprecated id_xipki_ext_authorizationTemplate := id_xipki_ext {3}

    private static final ASN1ObjectIdentifier id_xipki_cmp =
        id_xipki.branch("2");

    // deprecated ASN1ObjectIdentifier id_xipki_cmp_cmpGenmsg =
    // id_xipki_cmp.branch("1");

    // deprecated id_xipki_cmp_cacerts = id_xipki_cmp {2};

    public static final ASN1ObjectIdentifier id_xipki_cmp_kem_encapkey =
        initOid(id_xipki_cmp.branch("3"), "xipki-cmp-kem-encapkey");

    private static final ASN1ObjectIdentifier id_xipki_alg =
        id_xipki.branch("3");

    public static final ASN1ObjectIdentifier id_alg_dhPop_x25519 =
        initOid(id_xipki_alg.branch("1"), "xipki-alg-dhPop-x25519");

    public static final ASN1ObjectIdentifier id_alg_dhPop_x448 =
        initOid(id_xipki_alg.branch("2"), "xipki-alg-dhPop-x448");

    public static final ASN1ObjectIdentifier id_alg_KEM_HMAC_SHA256 =
        initOid(id_xipki_alg.branch("3"), "xipki-alg-KEM-HMAC-SHA256");

  } // class Xipki

  public static class PolicyIdentifier {

    public static final ASN1ObjectIdentifier id_anyPolicy =
        initOid("2.5.29.32.0", "Any Policy");
    public static final ASN1ObjectIdentifier id_domain_validated =
        initOid("2.23.140.1.2.1", "Domain Validation (DV)");
    public static final ASN1ObjectIdentifier id_organization_validated =
        initOid("2.23.140.1.2.2", "Organization Validation (OV)");
    public static final ASN1ObjectIdentifier id_individual_validated =
        initOid("2.23.140.1.2.3", "Individual Validation (IV)");

    public static final ASN1ObjectIdentifier extended_validation = initOid(
        "2.23.140.1.1", "Extended Validation (EV)");

    public static final ASN1ObjectIdentifier id_cp_ipAddr_asNumber = initOid(
        "1.3.6.1.5.5.7.14.2", "id-cp-ipAddr-asNumber");

    public static final ASN1ObjectIdentifier id_cp_ipAddr_asNumber_v2 = initOid(
        "1.3.6.1.5.5.7.14.3", "id-cp-ipAddr-asNumber-v2");

    /* Remote SIM Provisioning Role Certificate Issuer */
    public static final ASN1ObjectIdentifier id_rspRole_ci = initOid(
        "2.23.146.1.2.1.0", "id-rspRole-ci");

    /* Remote SIM Provisioning Role eUIC */
    public static final ASN1ObjectIdentifier id_rspRole_euicc = initOid(
        "2.23.146.1.2.1.1", "id-rspRole-euicc");

    /* Remote SIM Provisioning Role eUICC Manufacturer */
    public static final ASN1ObjectIdentifier id_rspRole_eum = initOid(
        "2.23.146.1.2.1.2", "id-rspRole-eum");

    /* Remote SIM Provisioning Role SM-DP+ TLS */
    public static final ASN1ObjectIdentifier id_rspRole_dp_tls = initOid(
        "2.23.146.1.2.1.3", "id-rspRole-dp-tls");

    /* Remote SIM Provisioning Role SM-DP+ Authentication */
    public static final ASN1ObjectIdentifier id_rspRole_dp_auth = initOid(
        "2.23.146.1.2.1.4", "id-rspRole-dp-auth");

    /* Remote SIM Provisioning Role SM-DP+ Profile Binding */
    public static final ASN1ObjectIdentifier id_rspRole_dp_pb = initOid(
        "2.23.146.1.2.1.5", "id-rspRole-dp-pb");

    /* Remote SIM Provisioning Role SM-DS TLS */
    public static final ASN1ObjectIdentifier id_rspRole_ds_tls = initOid(
        "2.23.146.1.2.1.6", "id-rspRole-ds-tls");

    /* Remote SIM Provisioning Role SM-DS Authentication */
    public static final ASN1ObjectIdentifier id_rspRole_ds_auth = initOid(
        "2.23.146.1.2.1.7", "id-rspRole-ds-auth");

  }

  public static class PolicyQualifierId {

    public static final ASN1ObjectIdentifier cps =
        initOid("1.3.6.1.5.5.7.2.1", "CPS");
    public static final ASN1ObjectIdentifier userNotice =
        initOid("1.3.6.1.5.5.7.2.2", "User Notice");
  }

  public static class DN {

    /**
     * country code - StringType(SIZE(2)).
     */
    public static final ASN1ObjectIdentifier country =
        initOid("2.5.4.6", "at-country");

    /**
     * organization - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier organization =
        initOid("2.5.4.10", "at-organization");

    /**
     * organizationIdentifier - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier organizationIdentifier =
        initOid("2.5.4.97", "at-organizationIdentifier");

    /**
     * organizational unit name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier organizationalUnit =
        initOid("2.5.4.11", "at-organizationalUnit");

    /**
     * Title.
     */
    public static final ASN1ObjectIdentifier title =
        initOid("2.5.4.12", "at-title");

    /**
     * common name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier commonName =
        initOid("2.5.4.3", "at-commonName");

    /**
     * device serial number name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier serialNumber =
        initOid("2.5.4.5", "at-serialNumber");

    /**
     * street - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier street =
        initOid("2.5.4.9", "at-street");

    /**
     * locality name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier locality =
        initOid("2.5.4.7", "at-locality");

    /**
     * state, or province name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier state =
        initOid("2.5.4.8", "at-state");

    /**
     * Naming attributes of type X520name.
     */
    public static final ASN1ObjectIdentifier surname =
        initOid("2.5.4.4", "at-surname");

    public static final ASN1ObjectIdentifier givenName =
        initOid("2.5.4.42", "at-givenName");

    public static final ASN1ObjectIdentifier initials =
        initOid("2.5.4.43", "at-initials");

    public static final ASN1ObjectIdentifier generationQualifier =
        initOid("2.5.4.44", "at-generationQualifier");

    public static final ASN1ObjectIdentifier uniqueIdentifier =
        initOid("2.5.4.45", "at-uniqueIdentifier");

    /**
     * businessCategory - DirectoryString(SIZE(1..128)
     */
    public static final ASN1ObjectIdentifier businessCategory =
        initOid("2.5.4.15", "at-businessCategory");

    /**
     * postalCode - DirectoryString(SIZE(1..40)
     */
    public static final ASN1ObjectIdentifier postalCode =
        initOid("2.5.4.17", "at-postalCode");

    /**
     * dnQualifier - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier dnQualifier =
        initOid("2.5.4.46", "at-dnQualifier");

    /**
     * RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier pseudonym =
        initOid("2.5.4.65", "at-pseudonym");

    /**
     * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z.
     */
    public static final ASN1ObjectIdentifier dateOfBirth =
        initOid("1.3.6.1.5.5.7.9.1", "at-dateOfBirth");

    /**
     * RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
     */
    public static final ASN1ObjectIdentifier placeOfBirth =
        initOid("1.3.6.1.5.5.7.9.2", "at-placeOfBirth");

    /**
     * RFC 3039 Gender - PrintableString (SIZE(1))-- "M", "F", "m" or "f".
     */
    public static final ASN1ObjectIdentifier gender =
        initOid("1.3.6.1.5.5.7.9.3", "at-gender");

    /**
     * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2))
     *   -- ISO 3166 codes only.
     */
    public static final ASN1ObjectIdentifier countryOfCitizenship =
        initOid("1.3.6.1.5.5.7.9.4", "at-countryOfCitizenship");

    /**
     * RFC 3039 CountryOfResidence - PrintableString (SIZE (2))
     *   -- ISO 3166 codes only.
     */
    public static final ASN1ObjectIdentifier countryOfResidence =
        initOid("1.3.6.1.5.5.7.9.5", "at-countryOfResidence");

    /**
     * ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier nameAtBirth =
        initOid("1.3.36.8.3.14", "at-nameAtBirth");

    /**
     * RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
     * DirectoryString(SIZE(1..30))
     */
    public static final ASN1ObjectIdentifier postalAddress =
        initOid("2.5.4.16", "at-postalAddress");

    /**
     * RFC 2256 dmdName.
     */
    public static final ASN1ObjectIdentifier dmdName =
        initOid("2.5.4.54", "at-dmdName");

    /**
     * id-at-telephoneNumber.
     */
    public static final ASN1ObjectIdentifier telephoneNumber =
        initOid("2.5.4.20", "at-telephoneNumber");

    /**
     * id-at-name.
     */
    public static final ASN1ObjectIdentifier name =
        initOid("2.5.4.41", "at-name");

    /**
     * Email address (RSA PKCS#9 extension) - IA5String.
     *
     * <p>Note: if you're trying to be ultra orthodox, don't use this!
     * It shouldn't be in here.
     */
    public static final ASN1ObjectIdentifier emailAddress = initOid(
        "1.2.840.113549.1.9.1", "pkcs9-at-emailAddress");

    /**
     * more from PKCS#9.
     */
    public static final ASN1ObjectIdentifier unstructuredName = initOid(
        "1.2.840.113549.1.9.2", "pkcs9-at-unstructuredName");

    public static final ASN1ObjectIdentifier unstructuredAddress = initOid(
        "1.2.840.113549.1.9.8", "pkcs9-at-unstructuredAddress");

    /*
    * others...
    */
    public static final ASN1ObjectIdentifier domainComponent = initOid(
        "0.9.2342.19200300.100.1.25", "at-domainComponent");

    /**
     * LDAP User id.
     */
    public static final ASN1ObjectIdentifier userid =
        initOid("0.9.2342.19200300.100.1.1", "userid");

    /**
     * jurisdictionOfIncorporationLocalityName.
     */
    public static final ASN1ObjectIdentifier jurIncorporationLocality = initOid(
        "1.3.6.1.4.1.311.60.2.1.1", "at-jurIncorporationLocality");

    /**
     * jurisdictionOfIncorporationStateOrProvinceName.
     */
    public static final ASN1ObjectIdentifier jurIncorporationState = initOid(
        "1.3.6.1.4.1.311.60.2.1.2", "at-jurIncorporationState");

    /**
     * jurisdictionOfIncorporationCountryName.
     */
    public static final ASN1ObjectIdentifier jurIncorporationCountry = initOid(
        "1.3.6.1.4.1.311.60.2.1.3", "at-jurIncorporationCountry");
  }

  // extended key usage
  public static final class XKU {

    public static final ASN1ObjectIdentifier id_kp_anyExtendedKeyUsage =
        initOid("2.5.29.37.0", "kp-any");

    /**
     * TLS WWW client authentication.
     * Key usage bits that may be consistent: digitalSignature and/or
     * keyAgreement.
     */
    public static final ASN1ObjectIdentifier id_kp_clientAuth = initOid(
        "1.3.6.1.5.5.7.3.2", "kp-clientAuth");

    /**
     * Signing of downloadable executable code.
     * Key usage bits that may be consistent: digitalSignature.
     */
    public static final ASN1ObjectIdentifier id_kp_codeSigning = initOid(
        "1.3.6.1.5.5.7.3.3", "kp-codeSigning");

    /**
     * Email protection.
     * Key usage bits that may be consistent: digitalSignature,
     * nonRepudiation, and/or (keyEncipherment or keyAgreement).
     */
    public static final ASN1ObjectIdentifier id_kp_emailProtection =
        initOid("1.3.6.1.5.5.7.3.4", "kp-emailProtection");

    /**
     * ETSI TSL Signing.
     */
    public static final ASN1ObjectIdentifier id_kp_etsiTslSigning =
        initOid("0.4.0.2231.3.0", "kp-etsiTslSigning");

    /**
     * ICAO Master List Signing.
     */
    public static final ASN1ObjectIdentifier id_kp_icaoMasterListSigning =
        initOid("2.23.136.1.1.3", "kp-icaoMasterListSigning");

    /**
     * Internet Key Exchange for IPsec.
     */
    public static final ASN1ObjectIdentifier id_kp_ikeForIpsec =
        initOid("1.3.6.1.5.5.7.3.17", "kp-ikeForIpsec");

    /**
     * Intel AMT management.
     */
    public static final ASN1ObjectIdentifier id_kp_intelAmtManagement =
        initOid("2.16.840.1.113741.1.2.3", "kp-intelAmtManagement");

    /**
     * This purpose has been included in a predecessor draft of RFC 3280
     * and therefore continue to be listed by this implementation.
     *
     * <p>IP security end system.
     */
    public static final ASN1ObjectIdentifier id_kp_ipsecEndSystem =
        initOid("1.3.6.1.5.5.7.3.5", "kp-ipsecEndSystem");

    /**
     * This purpose has been included in a predecessor draft of RFC 3280
     * and therefore continue to be listed by this implementation.
     *
     * <p>IP security tunnel termination.
     */
    public static final ASN1ObjectIdentifier id_kp_ipsecTunnel =
        initOid("1.3.6.1.5.5.7.3.6", "kp-ipsecTunnel");

    /**
     * This purpose has been included in a predecessor draft of RFC 3280
     * and therefore continue to be listed by this implementation.
     *
     * <p>IP security user.
     */
    public static final ASN1ObjectIdentifier id_kp_ipsecUser =
        initOid("1.3.6.1.5.5.7.3.7", "kp-ipsecUser");

    /**
     * Kerberos Client Authentication.
     */
    public static final ASN1ObjectIdentifier
        id_kp_kerberosClientAuthentication = initOid(
            "1.3.6.1.5.2.3.4", "kp-kerberosClientAuthentication");

    /**
     * Kerberos Key Distribution Center.
     */
    public static final ASN1ObjectIdentifier id_kp_kerberosKdc = initOid(
        "1.3.6.1.5.2.3.5", "kp-kerberosKdc");

    /**
     * Microsoft Commercial Code Signing.
     */
    public static final ASN1ObjectIdentifier
        id_kp_microsoftCommercialCodeSigning = initOid(
        "1.3.6.1.4.1.311.2.1.22", "kp-microsoftCommercialCodeSigning");

    /**
     * Microsoft Document Signing.
     */
    public static final ASN1ObjectIdentifier id_kp_microsoftDocumentSigning =
        initOid("1.3.6.1.4.1.311.10.3.12", "kp-microsoftDocumentSigning");

    /**
     * Microsoft Encrypted File System (EFS).
     */
    public static final ASN1ObjectIdentifier id_kp_microsoftEfs = initOid(
        "1.3.6.1.4.1.311.10.3.4", "kp-microsoftEfs");

    /**
     * Microsoft EFS Recovery.
     */
    public static final ASN1ObjectIdentifier id_kp_microsoftEfsRecovery =
        initOid("1.3.6.1.4.1.311.10.3.4.1", "kp-microsoftEfsRecovery");

    /**
     * Microsoft Individual Code Signing.
     */
    public static final ASN1ObjectIdentifier
        id_kp_microsoftIndividualCodeSigning = initOid(
        "1.3.6.1.4.1.311.2.1.21", "kp-microsoftIndividualCodeSigning");

    /**
     * Microsoft Smart Card Logon.
     */
    public static final ASN1ObjectIdentifier id_kp_microsoftSmartCardLogon =
        initOid("1.3.6.1.4.1.311.20.2.2", "kp-microsoftSmartCardLogon");

    /**
     * Signing OCSP responses
     * Key usage bits that may be consistent: digitalSignature and/or
     * nonRepudiation.
     */
    public static final ASN1ObjectIdentifier id_kp_ocspSigning =
        initOid("1.3.6.1.5.5.7.3.9", "kp-ocspSigning");

    /**
     * PIV Card Authentication.
     */
    public static final ASN1ObjectIdentifier id_kp_pivCardAuthentication =
        initOid("2.16.840.1.101.3.6.8", "kp-pivCardAuthentication");

    /**
     * PDF Signing.
     */
    public static final ASN1ObjectIdentifier id_kp_pdfSigning =
        initOid("1.2.840.113583.1.1.5", "kp-pdfSigning");

    /**
     * SCVP Client.
     */
    public static final ASN1ObjectIdentifier id_kp_scvpClient =
        initOid("1.3.6.1.5.5.7.3.16", "kp-scvpClient");

    /**
     * SCVP Server.
     */
    public static final ASN1ObjectIdentifier id_kp_scvpServer =
        initOid("1.3.6.1.5.5.7.3.15", "kp-scvpServer");

    /**
     * TLS WWW server authentication
     * Key usage bits that may be consistent: digitalSignature,
     * keyEncipherment or keyAgreement.
     */
    public static final ASN1ObjectIdentifier id_kp_serverAuth =
        initOid("1.3.6.1.5.5.7.3.1", "kp-serverAuth");

    /**
     * SIP Domain.
     */
    public static final ASN1ObjectIdentifier id_kp_sipDomain =
        initOid("1.3.6.1.5.5.7.3.20", "kp-sipDomain");

    /**
     * SSH Client.
     */
    public static final ASN1ObjectIdentifier id_kp_sshClient =
        initOid("1.3.6.1.5.5.7.3.21", "kp-sshClient");

    /**
     * SSH Server.
     */
    public static final ASN1ObjectIdentifier id_kp_sshServer =
        initOid("1.3.6.1.5.5.7.3.22", "kp-sshServer");

    /**
     * Binding the hash of an object to a time
     * Key usage bits that may be consistent: digitalSignature and/or
     * nonRepudiation.
     */
    public static final ASN1ObjectIdentifier id_kp_timeStamping =
        initOid("1.3.6.1.5.5.7.3.8", "kp-timeStamping");

    public static final ASN1ObjectIdentifier id_kp_cmcCA =
        initOid("1.3.6.1.5.5.7.3.27", "kp-cmcCA");

    public static final ASN1ObjectIdentifier id_kp_cmcRA =
        initOid("1.3.6.1.5.5.7.3.28", "kp-cmcRA");

    public static final ASN1ObjectIdentifier id_kp_cmcKGA =
        initOid("1.3.6.1.5.5.7.3.32", "kp-cmcKGA");

    public static final ASN1ObjectIdentifier id_kp_appleSafariExtensionSigning =
        initOid("1.2.840.113635.100.4.8", "kp-appleSafariExtensionSigning");

    public static final ASN1ObjectIdentifier id_kp_macInstallerPackageSigning =
        initOid("1.2.840.113635.100.4.9", "kp-macInstallerPackageSigning");

    public static final ASN1ObjectIdentifier
        id_kp_macAppStoreInstallerPackageSigning = initOid(
        "1.2.840.113635.100.4.10", "kp-macAppStoreInstallerPackageSigning");

    // Certificate Transparency (RFC 6962)
    public static final ASN1ObjectIdentifier id_kp_certificateTransparency =
        initOid(
        "1.3.6.1.4.1.11129.2.4.4", "kp-certificateTransparency");
  }

  public static final class Extn {

    /**
     * Subject Directory Attributes
     */
    public static final ASN1ObjectIdentifier subjectDirectoryAttributes =
        initOid("2.5.29.9", "subjectDirectoryAttributes");

    /**
     * Subject Key Identifier
     */
    public static final ASN1ObjectIdentifier subjectKeyIdentifier =
        initOid("2.5.29.14", "subjectKeyIdentifier");

    /**
     * Key Usage
     */
    public static final ASN1ObjectIdentifier keyUsage =
        initOid("2.5.29.15", "keyUsage");

    /**
     * Private Key Usage Period
     */
    public static final ASN1ObjectIdentifier privateKeyUsagePeriod =
        initOid("2.5.29.16", "privateKeyUsagePeriod");

    /**
     * Subject Alternative Name
     */
    public static final ASN1ObjectIdentifier subjectAlternativeName =
        initOid("2.5.29.17", "subjectAlternativeName");

    /**
     * Issuer Alternative Name
     */
    public static final ASN1ObjectIdentifier issuerAlternativeName =
        initOid("2.5.29.18", "issuerAlternativeName");

    /**
     * Basic Constraints
     */
    public static final ASN1ObjectIdentifier basicConstraints =
        initOid("2.5.29.19", "basicConstraints");

    /**
     * CRL Number
     */
    public static final ASN1ObjectIdentifier cRLNumber =
        initOid("2.5.29.20", "cRLNumber");

    /**
     * Reason code
     */
    public static final ASN1ObjectIdentifier reasonCode =
        initOid("2.5.29.21", "reasonCode");

    /**
     * Hold Instruction Code
     */
    public static final ASN1ObjectIdentifier instructionCode =
        initOid("2.5.29.23", "instructionCode");

    /**
     * Invalidity Date
     */
    public static final ASN1ObjectIdentifier invalidityDate =
        initOid("2.5.29.24", "invalidityDate");

    /**
     * Delta CRL indicator
     */
    public static final ASN1ObjectIdentifier deltaCRLIndicator =
        initOid("2.5.29.27", "deltaCRLIndicator");

    /**
     * Issuing Distribution Point
     */
    public static final ASN1ObjectIdentifier issuingDistributionPoint =
        initOid("2.5.29.28", "issuingDistributionPoint");

    /**
     * Certificate Issuer
     */
    public static final ASN1ObjectIdentifier certificateIssuer =
        initOid("2.5.29.29", "certificateIssuer");

    /**
     * Name Constraints
     */
    public static final ASN1ObjectIdentifier nameConstraints =
        initOid("2.5.29.30", "nameConstraints");

    /**
     * CRL Distribution Points
     */
    public static final ASN1ObjectIdentifier cRLDistributionPoints =
        initOid("2.5.29.31", "cRLDistributionPoints");

    /**
     * Certificate Policies
     */
    public static final ASN1ObjectIdentifier certificatePolicies =
        initOid("2.5.29.32", "certificatePolicies");

    /**
     * Policy Mappings
     */
    public static final ASN1ObjectIdentifier policyMappings =
        initOid("2.5.29.33", "policyMappings");

    /**
     * Authority Key Identifier
     */
    public static final ASN1ObjectIdentifier authorityKeyIdentifier =
        initOid("2.5.29.35", "authorityKeyIdentifier");

    /**
     * Policy Constraints
     */
    public static final ASN1ObjectIdentifier policyConstraints =
        initOid("2.5.29.36", "policyConstraints");

    /**
     * Extended Key Usage
     */
    public static final ASN1ObjectIdentifier extendedKeyUsage =
        initOid("2.5.29.37", "extendedKeyUsage");

    /**
     * Freshest CRL
     */
    public static final ASN1ObjectIdentifier freshestCRL =
        initOid("2.5.29.46", "freshestCRL");

    /**
     * Inhibit Any Policy
     */
    public static final ASN1ObjectIdentifier inhibitAnyPolicy =
        initOid("2.5.29.54", "inhibitAnyPolicy");

    /**
     * Authority Info Access
     */
    public static final ASN1ObjectIdentifier authorityInfoAccess =
        initOid("1.3.6.1.5.5.7.1.1", "authorityInfoAccess");

    /**
     * ipAddrBlocks
     */
    public static final ASN1ObjectIdentifier ipAddrBlocks =
        initOid("1.3.6.1.5.5.7.1.7", "sbgp-ipAddrBlock");

    /**
     * autonomousSysIds
     */
    public static final ASN1ObjectIdentifier autonomousSysIds =
        initOid("1.3.6.1.5.5.7.1.8", "sbgp-autonomousSysNum");

    /**
     * ipAddrBlocks-v2
     */
    public static final ASN1ObjectIdentifier ipAddrBlocksV2 =
        initOid("1.3.6.1.5.5.7.1.28", "sbgp-ipAddrBlockV2");

    /**
     * autonomousSysIds-v2
     */
    public static final ASN1ObjectIdentifier autonomousSysIdsV2 =
        initOid("1.3.6.1.5.5.7.1.29", "sbgp-autonomousSysNumV2");

    /**
     * Subject Info Access
     */
    public static final ASN1ObjectIdentifier subjectInfoAccess =
        initOid("1.3.6.1.5.5.7.1.11", "subjectInfoAccess");

    /**
     * Logo Type
     */
    public static final ASN1ObjectIdentifier logoType =
        initOid("1.3.6.1.5.5.7.1.12", "logoType");

    /**
     * BiometricInfo
     */
    public static final ASN1ObjectIdentifier biometricInfo =
        initOid("1.3.6.1.5.5.7.1.2", "biometricInfo");

    /**
     * QCStatements
     */
    public static final ASN1ObjectIdentifier qCStatements =
        initOid("1.3.6.1.5.5.7.1.3", "qCStatements");

    /**
     * Audit identity extension in attribute certificates.
     */
    public static final ASN1ObjectIdentifier auditIdentity =
        initOid("1.3.6.1.5.5.7.1.4", "auditIdentity");

    /**
     * NoRevAvail extension in attribute certificates.
     */
    public static final ASN1ObjectIdentifier noRevAvail =
        initOid("2.5.29.56", "noRevAvail");

    /**
     * TargetInformation extension in attribute certificates.
     */
    public static final ASN1ObjectIdentifier targetInformation =
        initOid("2.5.29.55", "targetInformation");

    /**
     * Expired Certificates on CRL extension
     */
    public static final ASN1ObjectIdentifier expiredCertsOnCRL =
        initOid("2.5.29.60", "expiredCertsOnCRL");

    /**
     * the subject’s alternative public key information
     */
    public static final ASN1ObjectIdentifier subjectAltPublicKeyInfo =
        initOid("2.5.29.72", "subjectAltPublicKeyInfo");

    /**
     * the algorithm identifier for the alternative digital signature algorithm.
     */
    public static final ASN1ObjectIdentifier altSignatureAlgorithm =
        initOid("2.5.29.73", "altSignatureAlgorithm");

    /**
     * alternative signature shall be created by the issuer using its
     * alternative private key.
     */
    public static final ASN1ObjectIdentifier altSignatureValue =
        initOid("2.5.29.74", "altSignatureValue");

    /**
     * delta certificate extension - prototype value will change!
     */
    public static final ASN1ObjectIdentifier deltaCertificateDescriptor =
        initOid("2.16.840.1.114027.80.6.1", "deltaCertificateDescriptor");

    // OCSP
    public static final ASN1ObjectIdentifier id_pkix_ocsp_prefSigAlgs =
        initOid("1.3.6.1.5.5.7.48.1.8", "pkix-ocsp-prefSigAlgs");

    public static final ASN1ObjectIdentifier id_pkix_ocsp_extendedRevoke =
        initOid("1.3.6.1.5.5.7.48.1.9", "pkix-ocsp-extendedRevoke");

    public static final ASN1ObjectIdentifier id_pkix_ocsp_nocheck =
        initOid("1.3.6.1.5.5.7.48.1.5", "pkix-ocsp-nocheck");

    public static final ASN1ObjectIdentifier id_ad_timeStamping =
        initOid("1.3.6.1.5.5.7.48.3", "ad-timeStamping");

    public static final ASN1ObjectIdentifier id_ad_caRepository =
        initOid("1.3.6.1.5.5.7.48.5", "ad-caRepository");

    public static final ASN1ObjectIdentifier id_pe_tlsfeature =
        initOid("1.3.6.1.5.5.7.1.24", "pe-tlsfeature");

    public static final ASN1ObjectIdentifier id_dmtf_spdm_extension =
        Spdm.id_DMTF_SPDM_extension;

    // RFC 4262: SMIMECapatibilities
    public static final ASN1ObjectIdentifier id_smimeCapabilities =
        initOid("1.2.840.113549.1.9.15", "smimeCapabilities");

    // Certificate Transparency (RFC 6962)
    public static final ASN1ObjectIdentifier id_precertificate =
        initOid("1.3.6.1.4.1.11129.2.4.3", "CT Precertificate Poison");

    // Certificate Transparency (RFC 6962)
    public static final ASN1ObjectIdentifier id_SignedCertificateTimestampList =
        initOid("1.3.6.1.4.1.11129.2.4.2", "CT Precertificate SCTs");

    // CCC: Car Connectivity Consortium
    public static final ASN1ObjectIdentifier id_ccc_extn =
        new ASN1ObjectIdentifier("1.3.6.1.4.1.41577.5");

    public static final ASN1ObjectIdentifier id_ccc_K_Vehicle_Cert =
        initOid("1.3.6.1.4.1.41577.5.1", "CCC-K-Vehicle-Cert");
    public static final ASN1ObjectIdentifier id_ccc_F_External_CA_Cert =
        initOid("1.3.6.1.4.1.41577.5.2", "CCC-F-External-CA-Cert");
    public static final ASN1ObjectIdentifier id_ccc_E_Instance_CA_Cert =
        initOid("1.3.6.1.4.1.41577.5.3", "CCC-E-Instance-CA-Cert");
    public static final ASN1ObjectIdentifier id_ccc_H_Endpoint_Cert =
        initOid("1.3.6.1.4.1.41577.5.4", "CCC-H-Endpoint-Cert");

    public static final ASN1ObjectIdentifier id_ccc_P_VehicleOEM_Enc_Cert =
        initOid("1.3.6.1.4.1.41577.5.5", "CCC-P-VehicleOEM-Enc-Cert");
    public static final ASN1ObjectIdentifier id_ccc_Q_VehicleOEM_Sig_Cert =
        initOid("1.3.6.1.4.1.41577.5.6", "CCC-Q-VehicleOEM-Sig-Cert");
    public static final ASN1ObjectIdentifier id_ccc_Device_Enc_Cert =
        initOid("1.3.6.1.4.1.41577.5.7", "CCC-Device-Enc-Cert");
    public static final ASN1ObjectIdentifier id_ccc_Vehicle_Intermediate_Cert =
        initOid("1.3.6.1.4.1.41577.5.8", "CCC-Vehicle-Intermediate-Cert");
    public static final ASN1ObjectIdentifier id_ccc_J_VehicleOEM_CA_Cert =
        initOid("1.3.6.1.4.1.41577.5.9", "CCC-J-VehicleOEM-CA-Cert");
    public static final ASN1ObjectIdentifier id_ccc_M_VehicleOEM_CA_Cert =
        initOid("1.3.6.1.4.1.41577.5.10", "CCC-M-VehicleOEM-CA-Cert");
  }

  public static final class Secg {

    public static final ASN1ObjectIdentifier id_aes128_cbc_in_ecies =
        initOid("1.3.132.1.20.0", "aes128-cbc-in-ecies");

    public static final ASN1ObjectIdentifier id_ecies_specifiedParameters =
        initOid("1.3.132.1.8", "ecies-specifiedParameters");

    public static final ASN1ObjectIdentifier id_hmac_full_ecies =
        initOid("1.3.132.1.22", "hmac-full-ecies");
  }

  public static final class Algo {

    public static final ASN1ObjectIdentifier id_alg_unsigned = initOid(
        "1.3.6.1.5.5.7.6.36", "id-alg-unsigned");

    public static final ASN1ObjectIdentifier id_rsaEncryption = initOid(
        "1.2.840.113549.1.1.1", "id-rsaEncryption");

    public static final ASN1ObjectIdentifier id_ecPublicKey = initOid(
        "1.2.840.10045.2.1", "id-ecPublicKey");

    public static final ASN1ObjectIdentifier id_RSASSA_PSS = initOid(
        "1.2.840.113549.1.1.10", "RSASSA-PSS");

    public static final ASN1ObjectIdentifier id_RSAES_OAEP = initOid(
        "1.2.840.113549.1.1.7", "RSAES-OAEP");

    public static final ASN1ObjectIdentifier id_mgf1 = initOid(
        "1.2.840.113549.1.1.8", "mgf1");

    public static final ASN1ObjectIdentifier sm2sign_with_sm3 = initOid(
        "1.2.156.10197.1.501", "sm2sign-with-sm3");

    public static final ASN1ObjectIdentifier id_ml_dsa_44 = initOid(
        "2.16.840.1.101.3.4.3.17", "ml-dsa-44");

    public static final ASN1ObjectIdentifier id_ml_dsa_65 = initOid(
        "2.16.840.1.101.3.4.3.18", "ml-dsa-65");

    public static final ASN1ObjectIdentifier id_ml_dsa_87 = initOid(
        "2.16.840.1.101.3.4.3.19", "ml-dsa-87");

    public static final ASN1ObjectIdentifier id_ml_kem_512 = initOid(
        "2.16.840.1.101.3.4.4.1", "ml-kem-512");

    public static final ASN1ObjectIdentifier id_ml_kem_768 = initOid(
        "2.16.840.1.101.3.4.4.2", "ml-kem-768");

    public static final ASN1ObjectIdentifier id_ml_kem_1024 = initOid(
        "2.16.840.1.101.3.4.4.3", "ml-kem-1024");

    public static final ASN1ObjectIdentifier id_RSASSA_PSS_SHAKE128 = initOid(
        "1.3.6.1.5.5.7.6.30", "RSASSA-PSS-SHAKE128");

    public static final ASN1ObjectIdentifier id_RSASSA_PSS_SHAKE256 = initOid(
        "1.3.6.1.5.5.7.6.31", "RSASSA-PSS-SHAKE256");

    public static final ASN1ObjectIdentifier id_ecdsa_with_shake128 = initOid(
        "1.3.6.1.5.5.7.6.32", "ecdsa-with-shake128");

    public static final ASN1ObjectIdentifier id_ecdsa_with_shake256 = initOid(
        "1.3.6.1.5.5.7.6.33", "ecdsa-with-shake256");

    public static final ASN1ObjectIdentifier id_ecdsa_with_sha3_224 = initOid(
        "2.16.840.1.101.3.4.3.9", "ecdsa-with-sha3-224");

    public static final ASN1ObjectIdentifier id_ecdsa_with_sha3_256 = initOid(
        "2.16.840.1.101.3.4.3.10", "ecdsa-with-sha3-256");

    public static final ASN1ObjectIdentifier id_ecdsa_with_sha3_384 = initOid(
        "2.16.840.1.101.3.4.3.11", "ecdsa-with-sha3-384");

    public static final ASN1ObjectIdentifier id_ecdsa_with_sha3_512 = initOid(
        "2.16.840.1.101.3.4.3.12", "ecdsa-with-sha3-512");

    public static final ASN1ObjectIdentifier id_hmacWithSHA3_224 = initOid(
        "2.16.840.1.101.3.4.2.13", "hmacWithSHA3-224");

    public static final ASN1ObjectIdentifier id_hmacWithSHA3_256 = initOid(
        "2.16.840.1.101.3.4.2.14", "hmacWithSHA3-256");

    public static final ASN1ObjectIdentifier id_hmacWithSHA3_384 = initOid(
        "2.16.840.1.101.3.4.2.15", "hmacWithSHA3-384");

    public static final ASN1ObjectIdentifier id_hmacWithSHA3_512 = initOid(
        "2.16.840.1.101.3.4.2.16", "hmacWithSHA3-512");

    public static final ASN1ObjectIdentifier
        id_rsassa_pkcs1_v1_5_with_sha3_224 = initOid(
        "2.16.840.1.101.3.4.3.13", "rsassa-pkcs1-v1.5-with-sha3-224");

    public static final ASN1ObjectIdentifier
        id_rsassa_pkcs1_v1_5_with_sha3_256 = initOid(
        "2.16.840.1.101.3.4.3.14", "rsassa-pkcs1-v1.5-with-sha3-256");

    public static final ASN1ObjectIdentifier
        id_rsassa_pkcs1_v1_5_with_sha3_384 = initOid(
        "2.16.840.1.101.3.4.3.15", "rsassa-pkcs1-v1.5-with-sha3-384");

    public static final ASN1ObjectIdentifier
        id_rsassa_pkcs1_v1_5_with_sha3_512 = initOid(
        "2.16.840.1.101.3.4.3.16", "rsassa-pkcs1-v1.5-with-sha3-512");

    public static final ASN1ObjectIdentifier id_hmacWithSHA1 = initOid(
        "1.2.840.113549.2.7", "hmacWithSHA1");

    public static final ASN1ObjectIdentifier id_hmacWithSHA224 = initOid(
        "1.2.840.113549.2.8", "hmacWithSHA224");

    public static final ASN1ObjectIdentifier id_hmacWithSHA256 = initOid(
        "1.2.840.113549.2.9", "hmacWithSHA256");

    public static final ASN1ObjectIdentifier id_hmacWithSHA384 = initOid(
        "1.2.840.113549.2.10", "hmacWithSHA384");

    public static final ASN1ObjectIdentifier id_hmacWithSHA512 = initOid(
        "1.2.840.113549.2.11", "hmacWithSHA512");

    public static final ASN1ObjectIdentifier sha1WithRSAEncryption = initOid(
        "1.2.840.113549.1.1.5", "sha1WithRSAEncryption");

    public static final ASN1ObjectIdentifier sha224WithRSAEncryption = initOid(
        "1.2.840.113549.1.1.14", "sha224WithRSAEncryption");

    public static final ASN1ObjectIdentifier sha256WithRSAEncryption = initOid(
        "1.2.840.113549.1.1.11", "sha256WithRSAEncryption");

    public static final ASN1ObjectIdentifier sha384WithRSAEncryption = initOid(
        "1.2.840.113549.1.1.12", "sha384WithRSAEncryption");

    public static final ASN1ObjectIdentifier sha512WithRSAEncryption = initOid(
        "1.2.840.113549.1.1.13", "sha512WithRSAEncryption");

    public static final ASN1ObjectIdentifier ecdsa_with_SHA1 = initOid(
        "1.2.840.10045.4.1", "ecdsa-with-SHA1");

    public static final ASN1ObjectIdentifier ecdsa_with_SHA224 = initOid(
        "1.2.840.10045.4.3.1", "ecdsa-with-SHA224");

    public static final ASN1ObjectIdentifier ecdsa_with_SHA256 = initOid(
        "1.2.840.10045.4.3.2", "ecdsa-with-SHA256");

    public static final ASN1ObjectIdentifier ecdsa_with_SHA384 = initOid(
        "1.2.840.10045.4.3.3", "ecdsa-with-SHA384");

    public static final ASN1ObjectIdentifier ecdsa_with_SHA512 = initOid(
        "1.2.840.10045.4.3.4", "ecdsa-with-SHA512");

    public static final ASN1ObjectIdentifier AES128_GMAC = initOid(
        "2.16.840.1.101.3.4.1.9", "AES128-GMAC");

    public static final ASN1ObjectIdentifier AES192_GMAC = initOid(
        "2.16.840.1.101.3.4.1.29", "AES192-GMAC");

    public static final ASN1ObjectIdentifier AES256_GMAC = initOid(
        "2.16.840.1.101.3.4.1.49", "AES256-GMAC");

    public static final ASN1ObjectIdentifier id_aes128_GCM = initOid(
        "2.16.840.1.101.3.4.1.6", "AES128-GCM");

    public static final ASN1ObjectIdentifier id_aes192_GCM = initOid(
        "2.16.840.1.101.3.4.1.26", "AES192-GCM");

    public static final ASN1ObjectIdentifier id_aes256_GCM = initOid(
        "2.16.840.1.101.3.4.1.46", "AES256-GCM");

    public static final ASN1ObjectIdentifier id_sm3 = initOid(
        "1.2.156.10197.1.401", "id-sm3");

    public static final ASN1ObjectIdentifier id_sha1 = initOid(
        "1.3.14.3.2.26", "id-sha1");

    public static final ASN1ObjectIdentifier id_sha224 = initOid(
        "2.16.840.1.101.3.4.2.4", "id-sha224");

    public static final ASN1ObjectIdentifier id_sha256 = initOid(
        "2.16.840.1.101.3.4.2.1", "id-sha256");

    public static final ASN1ObjectIdentifier id_sha384 = initOid(
        "2.16.840.1.101.3.4.2.2", "id-sha384");

    public static final ASN1ObjectIdentifier id_sha512 = initOid(
        "2.16.840.1.101.3.4.2.3", "id-sha512");

    public static final ASN1ObjectIdentifier id_sha3_224 = initOid(
        "2.16.840.1.101.3.4.2.7", "id-sha3-224");

    public static final ASN1ObjectIdentifier id_sha3_256 = initOid(
        "2.16.840.1.101.3.4.2.8", "id-sha3-256");

    public static final ASN1ObjectIdentifier id_sha3_384 = initOid(
        "2.16.840.1.101.3.4.2.9", "id-sha3-384");

    public static final ASN1ObjectIdentifier id_sha3_512 = initOid(
        "2.16.840.1.101.3.4.2.10", "id-sha3-512");

    public static final ASN1ObjectIdentifier id_shake128 = initOid(
        "2.16.840.1.101.3.4.2.11", "id-shake128");

    public static final ASN1ObjectIdentifier id_shake256 = initOid(
        "2.16.840.1.101.3.4.2.12", "id-shake256");

    public static final ASN1ObjectIdentifier id_PBKDF2 = initOid(
        "1.2.840.113549.1.5.12", "PBKDF2");

    public static final ASN1ObjectIdentifier id_PBES2 = initOid(
        "1.2.840.113549.1.5.13", "PBES2");

    public static final ASN1ObjectIdentifier id_RC2_CBC = initOid(
        "1.2.840.113549.3.2", "RC2-CBC");

    public static final ASN1ObjectIdentifier id_DES_EDE3_CBC = initOid(
        "1.2.840.113549.3.7", "DES-EDE3-CBC");

  }

  public static class Curve {

    public static final ASN1ObjectIdentifier id_X25519 = initOid(
        "1.3.101.110", "X25519");

    public static final ASN1ObjectIdentifier id_X448 = initOid(
        "1.3.101.111", "X448");

    public static final ASN1ObjectIdentifier id_ED25519 = initOid(
        "1.3.101.112", "ED25519");

    public static final ASN1ObjectIdentifier id_ED448 = initOid(
        "1.3.101.113", "ED448");

    public static final ASN1ObjectIdentifier sm2p256v1 = initOid(
        "1.2.156.10197.1.301", "sm2p256v1");

    public static final ASN1ObjectIdentifier frp256v1 = initOid(
        "1.2.250.1.223.101.256.1", "frp256v1");

    public static final ASN1ObjectIdentifier secp192r1 = initOid(
        "1.2.840.10045.3.1.1", "secp192r1");

    public static final ASN1ObjectIdentifier secp224r1 = initOid(
        "1.3.132.0.33", "secp224r1");

    public static final ASN1ObjectIdentifier secp256r1 = initOid(
        "1.2.840.10045.3.1.7", "secp256r1");

    public static final ASN1ObjectIdentifier secp384r1 = initOid(
        "1.3.132.0.34", "secp384r1");

    public static final ASN1ObjectIdentifier secp521r1 = initOid(
        "1.3.132.0.35", "secp521r1");

    public static final ASN1ObjectIdentifier brainpoolP192r1 = initOid(
        "1.3.36.3.3.2.8.1.1.3", "brainpoolP192r1");

    public static final ASN1ObjectIdentifier brainpoolP224r1 = initOid(
        "1.3.36.3.3.2.8.1.1.5", "brainpoolP224r1");

    public static final ASN1ObjectIdentifier brainpoolP256r1 = initOid(
        "1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1");

    public static final ASN1ObjectIdentifier brainpoolP384r1 = initOid(
        "1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1");

    public static final ASN1ObjectIdentifier brainpoolP512r1 = initOid(
        "1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1");

  }

  public static class Composite {
    // composite_sigs
    public static final ASN1ObjectIdentifier id_MLDSA44_RSA2048_PSS_SHA256 =
        initOid("1.3.6.1.5.5.7.6.37", "id-MLDSA44-RSA2048-PSS-SHA256");

    public static final ASN1ObjectIdentifier id_MLDSA44_RSA2048_PKCS15_SHA256 =
        initOid("1.3.6.1.5.5.7.6.38", "id-MLDSA44-RSA2048-PKCS15-SHA256");

    public static final ASN1ObjectIdentifier id_MLDSA44_Ed25519_SHA512 =
        initOid("1.3.6.1.5.5.7.6.39", "id-MLDSA44-Ed25519-SHA512");

    public static final ASN1ObjectIdentifier id_MLDSA44_ECDSA_P256_SHA256 =
        initOid("1.3.6.1.5.5.7.6.40", "id-MLDSA44-ECDSA-P256-SHA256");

    public static final ASN1ObjectIdentifier id_MLDSA65_RSA3072_PSS_SHA512 =
        initOid("1.3.6.1.5.5.7.6.41", "id-MLDSA65-RSA3072-PSS-SHA512");

    public static final ASN1ObjectIdentifier id_MLDSA65_RSA3072_PKCS15_SHA512 =
        initOid("1.3.6.1.5.5.7.6.42", "id-MLDSA65-RSA3072-PKCS15-SHA512");

    public static final ASN1ObjectIdentifier id_MLDSA65_RSA4096_PSS_SHA512 =
        initOid("1.3.6.1.5.5.7.6.43", "id-MLDSA65-RSA4096-PSS-SHA512");

    public static final ASN1ObjectIdentifier id_MLDSA65_RSA4096_PKCS15_SHA512 =
        initOid("1.3.6.1.5.5.7.6.44", "id-MLDSA65-RSA4096-PKCS15-SHA512");

    public static final ASN1ObjectIdentifier id_MLDSA65_ECDSA_P256_SHA512 =
        initOid("1.3.6.1.5.5.7.6.45", "id-MLDSA65-ECDSA-P256-SHA512");

    public static final ASN1ObjectIdentifier id_MLDSA65_ECDSA_P384_SHA512 =
        initOid("1.3.6.1.5.5.7.6.46", "id-MLDSA65-ECDSA-P384-SHA512");

    public static final ASN1ObjectIdentifier
        id_MLDSA65_ECDSA_brainpoolP256r1_SHA512 = initOid(
            "1.3.6.1.5.5.7.6.47", "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512");

    public static final ASN1ObjectIdentifier id_MLDSA65_Ed25519_SHA512 =
        initOid("1.3.6.1.5.5.7.6.48", "id-MLDSA65-Ed25519-SHA512");

    public static final ASN1ObjectIdentifier id_MLDSA87_ECDSA_P384_SHA512 =
        initOid("1.3.6.1.5.5.7.6.49", "id-MLDSA87-ECDSA-P384-SHA512");

    public static final ASN1ObjectIdentifier
        id_MLDSA87_ECDSA_brainpoolP384r1_SHA512 = initOid(
            "1.3.6.1.5.5.7.6.50", "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512");

    public static final ASN1ObjectIdentifier id_MLDSA87_Ed448_SHAKE256 =
        initOid("1.3.6.1.5.5.7.6.51",
            "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512");

    public static final ASN1ObjectIdentifier id_MLDSA87_RSA3072_PSS_SHA512 =
        initOid("1.3.6.1.5.5.7.6.52", "id-MLDSA87-RSA3072-PSS-SHA512");

    public static final ASN1ObjectIdentifier id_MLDSA87_RSA4096_PSS_SHA512 =
        initOid("1.3.6.1.5.5.7.6.53", "id-MLDSA87-RSA4096-PSS-SHA512");

    public static final ASN1ObjectIdentifier id_MLDSA87_ECDSA_P521_SHA512 =
        initOid("1.3.6.1.5.5.7.6.54", "id-MLDSA87-ECDSA-P521-SHA512");

    // composite_kem
    public static final ASN1ObjectIdentifier id_MLKEM768_RSA2048_SHA3_256 =
        initOid("1.3.6.1.5.5.7.6.55", "id-MLKEM768-RSA2048-SHA3-256");

    public static final ASN1ObjectIdentifier id_MLKEM768_RSA3072_SHA3_256 =
        initOid("1.3.6.1.5.5.7.6.56", "id-MLKEM768-RSA3072-SHA3-256");

    public static final ASN1ObjectIdentifier id_MLKEM768_RSA4096_SHA3_256 =
        initOid("1.3.6.1.5.5.7.6.57", "id-MLKEM768-RSA4096-SHA3-256");

    public static final ASN1ObjectIdentifier id_MLKEM768_X25519_SHA3_256 =
        initOid("1.3.6.1.5.5.7.6.58", "id-MLKEM768-X25519-SHA3-256");

    public static final ASN1ObjectIdentifier id_MLKEM768_ECDH_P256_SHA3_256 =
        initOid("1.3.6.1.5.5.7.6.59", "id-MLKEM768-ECDH-P256-SHA3-256");

    public static final ASN1ObjectIdentifier id_MLKEM768_ECDH_P384_SHA3_256 =
        initOid("1.3.6.1.5.5.7.6.60", "id-MLKEM768-ECDH-P384-SHA3-256");

    public static final ASN1ObjectIdentifier
        id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256 = initOid(
            "1.3.6.1.5.5.7.6.61", "id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256");

    public static final ASN1ObjectIdentifier id_MLKEM1024_RSA3072_SHA3_256 =
        initOid("1.3.6.1.5.5.7.6.62", "id-MLKEM1024-RSA3072-SHA3-256");

    public static final ASN1ObjectIdentifier id_MLKEM1024_ECDH_P384_SHA3_256 =
        initOid("1.3.6.1.5.5.7.6.63", "id-MLKEM1024-ECDH-P384-SHA3-256");

    public static final ASN1ObjectIdentifier
        id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256 = initOid(
            "1.3.6.1.5.5.7.6.64", "id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256");

    public static final ASN1ObjectIdentifier id_MLKEM1024_X448_SHA3_256 =
        initOid("1.3.6.1.5.5.7.6.65", "id-MLKEM1024-X448-SHA3-256");

    public static final ASN1ObjectIdentifier id_MLKEM1024_ECDH_P521_SHA3_256 =
        initOid("1.3.6.1.5.5.7.6.66", "id-MLKEM1024-ECDH-P521-SHA3-256");
  }

  public static class CMS {

    public static final ASN1ObjectIdentifier signedData = initOid(
        "1.2.840.113549.1.7.2", "signedData");

    public static final ASN1ObjectIdentifier data = initOid(
        "1.2.840.113549.1.7.1", "data");

    public static final ASN1ObjectIdentifier envelopedData = initOid(
        "1.2.840.113549.1.7.3", "envelopedData");
  }

  public static final class Misc {

    public static final ASN1ObjectIdentifier iso18033_kdf2 = initOid(
        "1.0.18033.2.5.2", "iso18033-kdf2");

    public static final ASN1ObjectIdentifier isismtt_at_certHash = initOid(
        "1.3.36.8.3.13", "isismtt-at-certHash");

  }

  public static final class PKCS9 {

    public static final ASN1ObjectIdentifier pkcs9_at_challengePassword =
        initOid("1.2.840.113549.1.9.7", "pkcs9-at-challengePassword");

    public static final ASN1ObjectIdentifier pkcs9_at_extensionRequest =
        initOid("1.2.840.113549.1.9.14", "pkcs9-at-extensionRequest");

    public static final ASN1ObjectIdentifier pkcs9_at_signingTime = initOid(
        "1.2.840.113549.1.9.5", "pkcs9-at-signingTime");

  }

  public static final class OCSP {

    public static final ASN1ObjectIdentifier id_pkix_ocsp_basic = initOid(
        "1.3.6.1.5.5.7.48.1.1", "pkix-ocsp-basic");

    public static final ASN1ObjectIdentifier id_pkix_ocsp_nonce = initOid(
        "1.3.6.1.5.5.7.48.1.2", "pkix-ocsp-nonce");

    public static final ASN1ObjectIdentifier id_pkix_ocsp_crl = initOid(
        "1.3.6.1.5.5.7.48.1.3", "pkix-ocsp-crl");

    public static final ASN1ObjectIdentifier id_pkix_ocsp_archive_cutoff =
        initOid("1.3.6.1.5.5.7.48.1.6", "pkix-ocsp-archive-cutoff");

    public static final ASN1ObjectIdentifier id_pkix_ocsp_response = initOid(
        "1.3.6.1.5.5.7.48.1.4", "pkix-ocsp-response");

  }

  public static class QCS {

    public static final ASN1ObjectIdentifier id_qcs_pkixQCSyntax_v1 =
        initOid("1.3.6.1.5.5.7.11.1", "qcs-pkixQCSyntax-v1");

    public static final ASN1ObjectIdentifier id_qcs_pkixQCSyntax_v2 =
        initOid("1.3.6.1.5.5.7.11.2", "qcs-pkixQCSyntax-v2");

    public static final ASN1ObjectIdentifier id_etsi_qcs_QcCompliance =
        initOid("0.4.0.1862.1.1", "etsi-qcs-QcCompliance");

    public static final ASN1ObjectIdentifier id_etsi_qcs_QcLimitValue =
        initOid("0.4.0.1862.1.2", "etsi-qcs-QcLimitValue");

    public static final ASN1ObjectIdentifier id_etsi_qcs_QcRetentionPeriod =
        initOid("0.4.0.1862.1.3", "etsi-qcs-QcRetentionPeriod");

    public static final ASN1ObjectIdentifier id_etsi_qcs_QcSSCD =
        initOid("0.4.0.1862.1.4", "etsi-qcs-QcSSCD");

    public static final ASN1ObjectIdentifier id_etsi_qcs_QcPDS =
        initOid("0.4.0.1862.1.5", "etsi-qcs-QcPDS");

    public static final ASN1ObjectIdentifier id_etsi_qcs_QcType =
        initOid("0.4.0.1862.1.6", "etsi-qcs-QcType");

    public static final ASN1ObjectIdentifier id_etsi_qcs_QcCClegislation =
        initOid("0.4.0.1862.1.7", "etsi-qcs-QcCClegislation");

    public static final ASN1ObjectIdentifier id_etsi_psd2_qcStatement =
        initOid("0.4.0.19495.2", "etsi-psd2-qcStatement");

  }

  public static final class Scep {

    public static final ASN1ObjectIdentifier transactionId = initOid(
        "2.16.840.1.113733.1.9.7", "transactionId");

    public static final ASN1ObjectIdentifier messageType = initOid(
        "2.16.840.1.113733.1.9.2", "messageType");

    public static final ASN1ObjectIdentifier pkiStatus = initOid(
        "2.16.840.1.113733.1.9.3", "pkiStatus");

    public static final ASN1ObjectIdentifier failInfo = initOid(
        "2.16.840.1.113733.1.9.4", "failInfo");

    public static final ASN1ObjectIdentifier senderNonce = initOid(
        "2.16.840.1.113733.1.9.5", "senderNonce");

    public static final ASN1ObjectIdentifier recipientNonce = initOid(
        "2.16.840.1.113733.1.9.6", "recipientNonce");

    public static final ASN1ObjectIdentifier failInfoText = initOid(
        "1.3.6.1.5.5.7.24.1", "failInfoText");

  }

  public static final class Spdm {

    private static final ASN1ObjectIdentifier id_spdm =
        new ASN1ObjectIdentifier("1.3.6.1.4.1.412.274");

    public static final ASN1ObjectIdentifier id_DMTF_device_info =
        initOid(id_spdm + ".1", "DMTF-device-info");

    public static final ASN1ObjectIdentifier id_DMTF_hardware_identity =
        initOid(id_spdm + ".2", "DMTF-hardware-identity");

    public static final ASN1ObjectIdentifier id_DMTF_eku_responder_auth =
        initOid(id_spdm + ".3", "DMTF-eku-responder-auth");

    public static final ASN1ObjectIdentifier id_DMTF_eku_requestor_auth =
        initOid(id_spdm + ".4", "DMTF-eku-requestor-auth");

    public static final ASN1ObjectIdentifier id_DMTF_mutable_certificate =
        initOid(id_spdm + ".5", "DMTF-mutable-certificate");

    public static final ASN1ObjectIdentifier id_DMTF_SPDM_extension =
        initOid(id_spdm + ".6", "DMTF-SPDM-extension");
  }

  private OIDs() {
  }

  public static String oidToDisplayName(ASN1ObjectIdentifier type) {
    String name = getName(Args.notNull(type, "type"));
    return (name == null) ? type.getId() : type.getId() + " (" + name + ")";
  }

  public static String getName(ASN1ObjectIdentifier type) {
    return getName(type.getId());
  }

  public static String getName(String type) {
    init();
    String name = oidNameMap.get(type);
    return name == null ? type : name;
  }

}
