// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.id;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.OIDs;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Lijun Liao (xipki)
 */
public class ExtensionID extends AbstractID {

  private static final Map<String, ExtensionID> typeMap = new HashMap<>();

  public static final ExtensionID subjectKeyIdentifier =
      initOf(OIDs.Extn.subjectKeyIdentifier, "SubjectKeyIdentifier");

  public static final ExtensionID keyUsage =
      initOf(OIDs.Extn.keyUsage, "KeyUsage");

  public static final ExtensionID subjectAltName =
      initOf(OIDs.Extn.subjectAlternativeName,
          "SubjectAlternativeName", "SubjectAltName");

  public static final ExtensionID subjectAlternativeName = subjectAltName;

  public static final ExtensionID basicConstraints =
      initOf(OIDs.Extn.basicConstraints, "BasicConstraints");

  public static final ExtensionID biometricInfo =
      initOf(OIDs.Extn.biometricInfo, "BiometricInfo");

  public static final ExtensionID crlDistributionPoints =
      initOf(OIDs.Extn.cRLDistributionPoints,
          "CRLDistributionPoints", "CRLDPs");

  public static final ExtensionID certificatePolicies =
      initOf(OIDs.Extn.certificatePolicies, "CertificatePolicies");

  public static final ExtensionID authorityKeyIdentifier =
      initOf(OIDs.Extn.authorityKeyIdentifier, "AuthorityKeyIdentifier");

  public static final ExtensionID extKeyUsage =
      initOf(OIDs.Extn.extendedKeyUsage, "ExtendedKeyUsage", "ExtKeyUsage");

  public static final ExtensionID extendedKeyUsage = extKeyUsage;

  public static final ExtensionID authorityInfoAccess =
      initOf(OIDs.Extn.authorityInfoAccess, "AuthorityInfoAccess");

  public static final ExtensionID signedCertificateTimestampList =
      initOf(OIDs.Extn.id_SignedCertificateTimestampList,
          "SignedCertificateTimestampList", "SCTL");

  public static final ExtensionID issuerAltName =
      initOf(OIDs.Extn.issuerAlternativeName,
          "IssuerAlternativeName", "IssuerAltName");

  public static final ExtensionID nameConstraints =
      initOf(OIDs.Extn.nameConstraints, "NameConstraints");

  public static final ExtensionID policyMappings =
      initOf(OIDs.Extn.policyMappings, "PolicyMappings");

  public static final ExtensionID policyConstraints =
      initOf(OIDs.Extn.policyConstraints, "PolicyConstrains");

  public static final ExtensionID privateKeyUsagePeriod =
      initOf(OIDs.Extn.privateKeyUsagePeriod, "PrivateKeyUsagePeriod");

  public static final ExtensionID freshestCRL =
      initOf(OIDs.Extn.freshestCRL, "FreshestCRL");

  public static final ExtensionID inhibitAnyPolicy =
      initOf(OIDs.Extn.inhibitAnyPolicy, "InhibitAnyPolicy");

  public static final ExtensionID subjectInfoAccess =
      initOf(OIDs.Extn.subjectInfoAccess, "SubjectInfoAccess");

  public static final ExtensionID preCertificate =
      initOf(OIDs.Extn.id_precertificate, "PreCertificate");

  public static final ExtensionID ocspNoCheck =
      initOf(OIDs.Extn.id_pkix_ocsp_nocheck, "OCSPNoCheck");

  public static final ExtensionID smimeCapabilities =
      initOf(OIDs.Extn.id_smimeCapabilities, "SMIMECapabilities");

  public static final ExtensionID qcStatements =
      initOf(OIDs.Extn.qCStatements, "QCStatements");

  public static final ExtensionID tlsFeature =
      initOf(OIDs.Extn.id_pe_tlsfeature, "TLSFeature");

  public static final ExtensionID CCC_K_VehicleCert =
      initOf(OIDs.Extn.id_ccc_K_Vehicle_Cert, "CCC-K-VehicleCert");

  public static final ExtensionID CCC_F_External_CACert =
      initOf(OIDs.Extn.id_ccc_F_External_CA_Cert, "CCC-F-ExternalCACert");

  public static final ExtensionID CCC_E_Instance_CACert =
      initOf(OIDs.Extn.id_ccc_E_Instance_CA_Cert, "CCC-E-InstanceCACert");

  public static final ExtensionID CCC_H_EndpointCert =
      initOf(OIDs.Extn.id_ccc_H_Endpoint_Cert, "CCC-H-EndpointCert");

  public static final ExtensionID CCC_P_VehicleOEMEncCert =
      initOf(OIDs.Extn.id_ccc_P_VehicleOEM_Enc_Cert, "CCC-P-VehicleOEMEncCert");

  public static final ExtensionID CCC_Q_VehicleOEMSigCert =
      initOf(OIDs.Extn.id_ccc_Q_VehicleOEM_Sig_Cert,
          "CCC-Q-VehicleOEMSigCert");

  public static final ExtensionID CCC_DeviceEncCert =
      initOf(OIDs.Extn.id_ccc_Device_Enc_Cert, "CCC-DeviceEncCert");

  public static final ExtensionID CCC_VehicleIntermediateCert =
      initOf(OIDs.Extn.id_ccc_Vehicle_Intermediate_Cert,
          "CCC-VehicleIntermediateCert");

  public static final ExtensionID CCC_J_VehicleOEMCACert =
      initOf(OIDs.Extn.id_ccc_J_VehicleOEM_CA_Cert, "CCC-J-VehicleOEMCACert");

  public static final ExtensionID CCC_M_VehicleOEMCACert =
      initOf(OIDs.Extn.id_ccc_M_VehicleOEM_CA_Cert, "CCC-M-VehicleOEMCACert");

  private ExtensionID(
      ASN1ObjectIdentifier x509, List<String> aliases) {
    super(x509, aliases);
  }

  private static ExtensionID initOf(
      ASN1ObjectIdentifier oid, String... aliases) {
    Args.notNull(oid, "oid");
    List<String> l = new ArrayList<>();
    if (aliases != null) {
      Collections.addAll(l, aliases);
    }
    l.add(oid.getId());
    return addToMap(new ExtensionID(oid, l), typeMap);
  }

  public static ExtensionID ofOid(ASN1ObjectIdentifier oid) {
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

    try {
      ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(c14n);
      return new ExtensionID(oid, Collections.singletonList(oid.getId()));
    } catch (RuntimeException e) {
      return null;
    }
  }

}
