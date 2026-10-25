// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.id;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.DiceOIDs;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.MrtdOIDs;
import org.xipki.codec.util.Args;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Extension ID.
 *
 * @author Lijun Liao (xipki)
 */
public class ExtensionID extends AbstractID {

  private static final Map<String, ExtensionID> typeMap = new HashMap<>();

  public static final ExtensionID subjectDirectoryAttributes =
      initOf(ExtensionOIDs.subjectDirectoryAttributes, "subjectDirectoryAttributes");

  public static final ExtensionID subjectKeyIdentifier =
      initOf(ExtensionOIDs.subjectKeyIdentifier, "SubjectKeyIdentifier");

  public static final ExtensionID keyUsage =
      initOf(ExtensionOIDs.keyUsage, "KeyUsage");

  public static final ExtensionID subjectAltName =
      initOf(ExtensionOIDs.subjectAlternativeName, "SubjectAlternativeName", "SubjectAltName");

  public static final ExtensionID subjectAlternativeName = subjectAltName;

  public static final ExtensionID basicConstraints =
      initOf(ExtensionOIDs.basicConstraints, "BasicConstraints");

  public static final ExtensionID biometricInfo =
      initOf(ExtensionOIDs.biometricInfo, "BiometricInfo");

  public static final ExtensionID crlDistributionPoints =
      initOf(ExtensionOIDs.cRLDistributionPoints, "CRLDistributionPoints", "CRLDPs");

  public static final ExtensionID certificatePolicies =
      initOf(ExtensionOIDs.certificatePolicies, "CertificatePolicies");

  public static final ExtensionID authorityKeyIdentifier =
      initOf(ExtensionOIDs.authorityKeyIdentifier, "AuthorityKeyIdentifier");

  public static final ExtensionID extKeyUsage =
      initOf(ExtensionOIDs.extendedKeyUsage, "ExtendedKeyUsage", "ExtKeyUsage");

  public static final ExtensionID extendedKeyUsage = extKeyUsage;

  public static final ExtensionID authorityInfoAccess =
      initOf(ExtensionOIDs.authorityInfoAccess, "AuthorityInfoAccess");

  public static final ExtensionID signedCertificateTimestampList =
      initOf(ExtensionOIDs.id_SignedCertificateTimestampList,
          "SignedCertificateTimestampList", "SCTL");

  public static final ExtensionID issuerAltName =
      initOf(ExtensionOIDs.issuerAlternativeName, "IssuerAlternativeName", "IssuerAltName");

  public static final ExtensionID nameConstraints =
      initOf(ExtensionOIDs.nameConstraints, "NameConstraints");

  public static final ExtensionID policyMappings =
      initOf(ExtensionOIDs.policyMappings, "PolicyMappings");

  public static final ExtensionID policyConstraints =
      initOf(ExtensionOIDs.policyConstraints, "PolicyConstrains");

  public static final ExtensionID privateKeyUsagePeriod =
      initOf(ExtensionOIDs.privateKeyUsagePeriod, "PrivateKeyUsagePeriod");

  public static final ExtensionID freshestCRL =
      initOf(ExtensionOIDs.freshestCRL, "FreshestCRL");

  public static final ExtensionID inhibitAnyPolicy =
      initOf(ExtensionOIDs.inhibitAnyPolicy, "InhibitAnyPolicy");

  public static final ExtensionID subjectInfoAccess =
      initOf(ExtensionOIDs.subjectInfoAccess, "SubjectInfoAccess");

  public static final ExtensionID preCertificate =
      initOf(ExtensionOIDs.id_precertificate, "PreCertificate");

  public static final ExtensionID ocspNoCheck =
      initOf(ExtensionOIDs.id_pkix_ocsp_nocheck, "OCSPNoCheck");

  public static final ExtensionID smimeCapabilities =
      initOf(ExtensionOIDs.id_smimeCapabilities, "SMIMECapabilities");

  public static final ExtensionID qcStatements =
      initOf(ExtensionOIDs.qCStatements, "QCStatements");

  public static final ExtensionID tlsFeature =
      initOf(ExtensionOIDs.id_pe_tlsfeature, "TLSFeature");

  public static final ExtensionID CCC_K_VehicleCert =
      initOf(ExtensionOIDs.id_ccc_K_Vehicle_Cert, "CCC-K-VehicleCert");

  public static final ExtensionID CCC_F_External_CACert =
      initOf(ExtensionOIDs.id_ccc_F_External_CA_Cert, "CCC-F-ExternalCACert");

  public static final ExtensionID CCC_E_Instance_CACert =
      initOf(ExtensionOIDs.id_ccc_E_Instance_CA_Cert, "CCC-E-InstanceCACert");

  public static final ExtensionID CCC_H_EndpointCert =
      initOf(ExtensionOIDs.id_ccc_H_Endpoint_Cert, "CCC-H-EndpointCert");

  public static final ExtensionID CCC_P_VehicleOEMEncCert =
      initOf(ExtensionOIDs.id_ccc_P_VehicleOEM_Enc_Cert, "CCC-P-VehicleOEMEncCert");

  public static final ExtensionID CCC_Q_VehicleOEMSigCert =
      initOf(ExtensionOIDs.id_ccc_Q_VehicleOEM_Sig_Cert, "CCC-Q-VehicleOEMSigCert");

  public static final ExtensionID CCC_DeviceEncCert =
      initOf(ExtensionOIDs.id_ccc_Device_Enc_Cert, "CCC-DeviceEncCert");

  public static final ExtensionID CCC_VehicleIntermediateCert =
      initOf(ExtensionOIDs.id_ccc_Vehicle_Intermediate_Cert, "CCC-VehicleIntermediateCert");

  public static final ExtensionID CCC_J_VehicleOEMCACert =
      initOf(ExtensionOIDs.id_ccc_J_VehicleOEM_CA_Cert, "CCC-J-VehicleOEMCACert");

  public static final ExtensionID CCC_M_VehicleOEMCACert =
      initOf(ExtensionOIDs.id_ccc_M_VehicleOEM_CA_Cert, "CCC-M-VehicleOEMCACert");

  public static final ExtensionID CCC_R_CertificationBodyCert =
      initOf(ExtensionOIDs.id_ccc_R_CertificationBody_Cert, "CCC-R-CertificationBodyCert");

  public static final ExtensionID CCC_S_SBxDKisIntermediateCACert =
      initOf(ExtensionOIDs.id_ccc_S_SBxDKis_Intermediate_CA_Cert,
          "CCC-S-SBxDKisIntermediateCACert");

  public static final ExtensionID CCC_T_SBxDKisEndpointCert =
      initOf(ExtensionOIDs.id_ccc_T_SBxDKis_Endpoint_Cert, "CCC-T-SBxDKisEndpointCert");

  public static final ExtensionID CCC_U_SBxDKisRootCACert =
      initOf(ExtensionOIDs.id_ccc_U_SBxDKis_RootCA_Cert, "CCC-U-SBxDKisRootCACert");

  public static final ExtensionID microsoft_CertificateTemplateName =
      initOf(ExtensionOIDs.id_microsoft_CertificateTemplateName,
          "Microsoft-CertificateTemplateName");

  public static final ExtensionID microsoft_CertificateTemplateInformation =
      initOf(ExtensionOIDs.id_microsoft_CertificateTemplateInformation,
          "Microsoft-CertificateTemplateInformation");

  public static final ExtensionID microsoft_SID =
      initOf(ExtensionOIDs.id_microsoft_SecurityIdentifier, "Microsoft-SID");

  public static final ExtensionID CN_residentIdCardNumber =
      initOf(ExtensionOIDs.id_cn_residentIdCardNumber, "CN-ResidentIdCardNumber");

  public static final ExtensionID CN_passportNumber =
      initOf(ExtensionOIDs.id_cn_passportNumber, "CN-PassportNumber");

  public static final ExtensionID CN_socialInsuranceNumber =
      initOf(ExtensionOIDs.id_cn_socialInsuranceNumber, "CN-SocialInsuranceNumber");

  public static final ExtensionID CN_UnifiedSocialCreditCode =
      initOf(ExtensionOIDs.id_cn_unifiedSocialCreditCode, "CN-UnifiedSocialCreditCode");

  public static final ExtensionID SPDM_Extension =
      initOf(ExtensionOIDs.id_dmtf_spdm_extension, "SPDM-Extension");

  public static final ExtensionID STIR_JWTClaimConstraints =
      initOf(ExtensionOIDs.id_pe_JWTClaimConstraints, "STIR-JWTClaimConstraints");

  public static final ExtensionID STIR_TNAuthList =
      initOf(ExtensionOIDs.id_pe_TNAuthList, "STIR-TNAuthList");

  // RPKI
  public static final ExtensionID IPAddrBlocks =
      initOf(ExtensionOIDs.IPAddrBlocks, "IPAddrBlocks");

  public static final ExtensionID IPAddrBlocksV2 =
      initOf(ExtensionOIDs.IPAddrBlocksV2, "IPAddrBlocksV2");

  public static final ExtensionID ASIdentifiers =
      initOf(ExtensionOIDs.ASIdentifiers, "ASIdentifiers");

  public static final ExtensionID ASIdentifiersV2 =
      initOf(ExtensionOIDs.ASIdentifiersV2, "ASIdentifiersV2");

  // BRSKI (RFC 8995)
  public static final ExtensionID masaUrl =
      initOf(ExtensionOIDs.id_pe_masa_url, "MASA-URL");

  // ICAO MRTD
  public static final ExtensionID MRTD_NameChange =
      initOf(MrtdOIDs.id_icao_mrtd_security_extensions_nameChange, "MRTD-NameChange");

  public static final ExtensionID MRTD_DocumentTypeList =
      initOf(MrtdOIDs.id_icao_mrtd_security_extensions_documentTypeList,
          "MRTD-DocumentTypeList");

  // DICE
  public static final ExtensionID dice_ueid =
      initOf(DiceOIDs.tcg_dice_ueid, "dice-ueid");

  private ExtensionID(Asn1Oid x509, List<String> aliases) {
    super(x509, aliases);
  }

  private static ExtensionID initOf(Asn1Oid oid, String... aliases) {
    Args.notNull(oid, "oid");
    List<String> l = new ArrayList<>();
    if (aliases != null) {
      Collections.addAll(l, aliases);
    }
    l.add(oid.getId());
    return addToMap(new ExtensionID(oid, l), typeMap);
  }

  public static ExtensionID ofOid(Asn1Oid oid) {
    Args.notNull(oid, "oid");
    ExtensionID attr = ofOidOrName(typeMap, oid.getId());
    if (attr != null) {
      return attr;
    }

    return new ExtensionID(oid, Collections.singletonList(oid.getId()));
  }

  public static ExtensionID ofOidOrName(String oidOrName) {
    String c14n = canonicalizeAlias(Args.notNull(oidOrName, "oidOrName"));
    ExtensionID id = ofOidOrName(typeMap, c14n);
    if (id != null) {
      return id;
    }

    Asn1Oid oid = new Asn1Oid(c14n);
    return new ExtensionID(oid, Collections.singletonList(oid.getId()));
  }

}
