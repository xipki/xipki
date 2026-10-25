// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.id;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.DiceOIDs;
import org.xipki.codec.asn1.oid.SpdmOIDs;
import org.xipki.codec.asn1.oid.TcgOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Extended Key Usage ID.
 *
 * @author Lijun Liao (xipki)
 */
// Please reflect changes here to
// org.xipki.shell.Completers.ExtKeyusageCompleter
public class ExtendedKeyUsageID extends AbstractID {

  private static final Map<String, ExtendedKeyUsageID> typeMap = new HashMap<>();

  // 2.5.29.37.0, any Extended Key Usage, anyExtendedKeyUsage
  public static final ExtendedKeyUsageID any = initOf("2.5.29.37.0", "any");

  // 1.3.6.1.5.5.7.3.1, TLS Server authentication, id-kp-serverAuth
  public static final ExtendedKeyUsageID serverAuth =
      initOf("1.3.6.1.5.5.7.3.1", "serverAuth");

  // 1.3.6.1.5.5.7.3.2, TLS Client Authentication, id-kp-clientAuth
  public static final ExtendedKeyUsageID clientAuth =
      initOf("1.3.6.1.5.5.7.3.2", "clientAuth");

  // 1.3.6.1.5.5.7.3.3, Code Signing, id-kp-codeSigning
  public static final ExtendedKeyUsageID codeSigning =
      initOf("1.3.6.1.5.5.7.3.3", "codeSigning");

  // 1.3.6.1.5.5.7.3.4, Email protection (S/MIME), id-kp-emailProtection
  public static final ExtendedKeyUsageID emailProtection =
      initOf("1.3.6.1.5.5.7.3.4", "emailProtection");

  // 1.3.6.1.5.5.7.3.8, Time Stamping, id-kp-timeStamping, timestamping
  public static final ExtendedKeyUsageID timestamping =
      initOf("1.3.6.1.5.5.7.3.8", "timestamping");

  // 1.3.6.1.5.5.7.3.9, OCSP Signing, id-kp-OCSPSigning
  public static final ExtendedKeyUsageID OCSPSigning =
      initOf("1.3.6.1.5.5.7.3.9", "OCSPSigning");

  // 1.3.6.1.5.2.3.4, Kerberos PKINIT Client Auth, id-pkinit-KPClientAuth
  public static final ExtendedKeyUsageID pkinitKPClientAuth =
      initOf("1.3.6.1.5.2.3.4", "pkinitKPClientAuth");

  // 1.3.6.1.5.2.3.5, Kerberos PKINIT KDC, id-pkinit-KPKdc
  public static final ExtendedKeyUsageID pkinitKPKDC =
      initOf("1.3.6.1.5.2.3.5", "pkinitKPKDC");

  // 1.3.6.1.5.5.7.3.21, SSH Client, id-kp-secureShellClient
  public static final ExtendedKeyUsageID sshClient =
      initOf("1.3.6.1.5.5.7.3.21", "sshClient");

  // 1.3.6.1.5.5.7.3.22, SSH Server, id-kp-secureShellServer
  public static final ExtendedKeyUsageID sshServer =
      initOf("1.3.6.1.5.5.7.3.22", "sshServer");

  // 1.3.6.1.5.5.7.3.35, Bundle Security, id-kp-bundleSecurity
  public static final ExtendedKeyUsageID bundleSecurity =
      initOf("1.3.6.1.5.5.7.3.35", "bundleSecurity");

  // 1.3.6.1.5.5.7.3.27, CMC Certification Authority, id-kp-cmcCA
  public static final ExtendedKeyUsageID cmcCA =
      initOf("1.3.6.1.5.5.7.3.27", "cmcCA");

  // 1.3.6.1.5.5.7.3.28, CMC Registration Authority, id-kp-cmcRA
  public static final ExtendedKeyUsageID cmcRA =
      initOf("1.3.6.1.5.5.7.3.28", "cmcRA");

  // 1.3.6.1.5.5.7.3.29, CMC Archive Server, id-kp-cmcArchive
  public static final ExtendedKeyUsageID cmcArchive =
      initOf("1.3.6.1.5.5.7.3.29", "cmcArchive");

  // 1.3.6.1.5.5.7.3.32, CMC Key Generation Authority, id-kp-cmKGA
  public static final ExtendedKeyUsageID cmKGA =
      initOf("1.3.6.1.5.5.7.3.32", "cmKGA");

  // 1.3.6.1.4.1.11129.2.4.4, Certificate Transparency, RFC 6962
  public static final ExtendedKeyUsageID certTransparency =
      initOf("1.3.6.1.4.1.11129.2.4.4", "certTransparency");

  public static final ExtendedKeyUsageID DMTF_eku_responder_auth =
      initOf(SpdmOIDs.id_DMTF_eku_responder_auth.getId(), "DMTF-eku-responder-auth");

  public static final ExtendedKeyUsageID DMTF_eku_requestor_auth =
      initOf(SpdmOIDs.id_DMTF_eku_requestor_auth.getId(), "DMTF-eku-requestor-auth");

  public static final ExtendedKeyUsageID tcg_dice_kp_identityInit =
      initOf(DiceOIDs.tcg_dice_kp_identityInit.getId(), "tcg-dice-kp-identityInit");

  public static final ExtendedKeyUsageID tcg_dice_kp_identityLoc =
      initOf(DiceOIDs.tcg_dice_kp_identityLoc.getId(), "tcg-dice-kp-identityLoc");

  public static final ExtendedKeyUsageID tcg_dice_kp_attestInit =
      initOf(DiceOIDs.tcg_dice_kp_attestInit.getId(), "tcg-dice-kp-attestInit");

  public static final ExtendedKeyUsageID tcg_dice_kp_attestLoc =
      initOf(DiceOIDs.tcg_dice_kp_attestLoc.getId(), "tcg-dice-kp-attestLoc");

  public static final ExtendedKeyUsageID tcg_dice_kp_assertInit =
      initOf(DiceOIDs.tcg_dice_kp_assertInit.getId(), "tcg-dice-kp-assertInit");

  public static final ExtendedKeyUsageID tcg_dice_kp_assertLoc =
      initOf(DiceOIDs.tcg_dice_kp_assertLoc.getId(), "tcg-dice-kp-assertLoc");

  public static final ExtendedKeyUsageID tcg_dice_kp_eca =
      initOf(DiceOIDs.tcg_dice_kp_eca.getId(), "tcg-dice-kp-eca");

  public static final ExtendedKeyUsageID tcg_kp_PlatformAttributeCertificate =
      initOf(TcgOIDs.tcg_kp_PlatformAttributeCertificate.getId(),
          "tcg-kp-PlatformAttributeCertificate");

  public static final ExtendedKeyUsageID tcg_kp_PlatformKeyCertificate =
      initOf(TcgOIDs.tcg_kp_PlatformKeyCertificate.getId(),
          "tcg-kp-PlatformKeyCertificate");

  public static final ExtendedKeyUsageID tcg_kp_DeltaPlatformAttributeCertificate =
      initOf(TcgOIDs.tcg_kp_DeltaPlatformAttributeCertificate.getId(),
          "tcg-kp-DeltaPlatformAttributeCertificate");

  public static final ExtendedKeyUsageID tcg_kp_DeltaPlatformKeyCertificate =
      initOf(TcgOIDs.tcg_kp_DeltaPlatformKeyCertificate.getId(),
          "tcg-kp-DeltaPlatformKeyCertificate");

  public static final ExtendedKeyUsageID tcg_kp_AdditionalPlatformAttributeCertificate =
      initOf(TcgOIDs.tcg_kp_AdditionalPlatformAttributeCertificate.getId(),
          "tcg-kp-AdditionalPlatformAttributeCertificate");

  public static final ExtendedKeyUsageID tcg_kp_AdditionalPlatformKeyCertificate =
      initOf(TcgOIDs.tcg_kp_AdditionalPlatformKeyCertificate.getId(),
          "tcg-kp-AdditionalPlatformKeyCertificate");

  private ExtendedKeyUsageID(Asn1Oid x509, List<String> aliases) {
    super(x509, aliases);
  }

  private static ExtendedKeyUsageID initOf(String oid, String... aliases) {
    Args.notNull(oid, "oid");
    List<String> l = new ArrayList<>();
    if (aliases != null) {
      l.addAll(Arrays.asList(aliases));
    }
    l.add(oid);
    return addToMap(new ExtendedKeyUsageID(new Asn1Oid(oid), l), typeMap);
  }

  public static ExtendedKeyUsageID ofOid(Asn1Oid oid) {
    Args.notNull(oid, "oid");
    ExtendedKeyUsageID attr = ofOidOrName(typeMap, oid.getId());
    if (attr != null) {
      return attr;
    }

    return new ExtendedKeyUsageID(oid, Collections.singletonList(oid.getId()));
  }

  public static ExtendedKeyUsageID ofOidOrName(String oidOrName) throws CodecException {
    String c14n = canonicalizeAlias(Args.notNull(oidOrName, "oidOrName"));
    ExtendedKeyUsageID id = ofOidOrName(typeMap, c14n);
    if (id != null) {
      return id;
    }

    try {
      Asn1Oid oid = new Asn1Oid(c14n);
      return new ExtendedKeyUsageID(oid, Collections.singletonList(oid.getId()));
    } catch (RuntimeException e) {
      throw new CodecException("invalid EKU " + oidOrName, e);
    }
  }

}
