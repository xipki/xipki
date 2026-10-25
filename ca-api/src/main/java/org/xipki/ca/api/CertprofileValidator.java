// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.KeyPurposeOIDs;
import org.xipki.pkix.asn1.x509.CertificatePolicies;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.ctrl.AuthorityInfoAccessControl;
import org.xipki.ca.api.profile.ctrl.CertDomain;
import org.xipki.ca.api.profile.ctrl.CertLevel;
import org.xipki.ca.api.profile.ctrl.ExtKeyUsageControl;
import org.xipki.ca.api.profile.ctrl.ExtensionControl;
import org.xipki.ca.api.profile.ctrl.ExtensionSpec;
import org.xipki.ca.api.profile.ctrl.ExtensionsControl;
import org.xipki.ca.api.profile.ctrl.RdnControl;
import org.xipki.ca.api.profile.ctrl.SubjectControl;
import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.util.misc.CollectionUtil;
import org.xipki.pkix.util.conf.Validity;
import org.xipki.pkix.util.conf.Validity.Unit;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Certprofile Validator.
 *
 * @author Lijun Liao (xipki)
 */
public class CertprofileValidator {

  private static final Validity maxCabEeValidity = new Validity(397, Unit.DAY);

  public static void validate(Certprofile certprofile) throws CertprofileException {
    StringBuilder msg = new StringBuilder();

    ExtensionsControl controls = certprofile.extensionsControl();
    List<Asn1Oid> types = controls.types();

    CertLevel certLevel = certprofile.certLevel();
    CertDomain certDomain = certprofile.certDomain();

    ExtensionSpec spec = ExtensionSpec.getExtensionSpec(certDomain, certLevel);

    // make sure that non-request extensions are not permitted in requests
    Set<Asn1Oid> set = new HashSet<>();
    for (Asn1Oid type : types) {
      ExtensionControl control = controls.getControl(type);
      if (control.isPermittedInRequest() && spec.isNonRequest(type)) {
        set.add(type);
      }
    }

    if (CollectionUtil.isNotEmpty(set)) {
      msg.append("extensions ").append(toString(set)).append(" must not be contained in request, ");
    }

    // make sure that non-permitted extensions are not configured
    set.clear();
    for (Asn1Oid type : types) {
      if (spec.isNotPermitted(type)) {
        set.add(type);
      }
    }

    if (CollectionUtil.isNotEmpty(set)) {
      msg.append("extensions ").append(toString(set)).append(" must not be contained, ");
    }

    // make sure that critical only extensions are not marked as non-critical.
    set.clear();
    for (Asn1Oid type : types) {
      ExtensionControl control = controls.getControl(type);
      if (control.isCritical() && spec.isNonCriticalOnly(type)) {
        set.add(type);
      }
    }

    if (CollectionUtil.isNotEmpty(set)) {
      msg.append("critical only extensions are marked as non-critical ")
          .append(toString(set)).append(", ");
    }

    // make sure that non-critical only extensions are not marked as critical.
    set.clear();
    for (Asn1Oid type : types) {
      ExtensionControl control = controls.getControl(type);
      if (!control.isCritical() && spec.isCriticalOnly(type)) {
        set.add(type);
      }
    }

    if (CollectionUtil.isNotEmpty(set)) {
      msg.append("non-critical only extensions are marked as critical ")
        .append(toString(set)).append(", ");
    }

    // make sure that required extensions are present
    set.clear();
    Set<Asn1Oid> requiredTypes = spec.requiredExtensions();

    for (Asn1Oid type : requiredTypes) {
      ExtensionControl extCtrl = controls.getControl(type);
      if (extCtrl == null || !extCtrl.isRequired()) {
        set.add(type);
      }
    }

    if (!set.isEmpty()) {
      msg.append("required extensions are not configured or not marked as required ")
        .append(toString(set)).append(", ");
    }

    if (certLevel == CertLevel.CROSS) {
      ExtensionsControl extnControls = certprofile.extensionsControl();
      Asn1Oid[] extnTypes = { ExtensionOIDs.subjectKeyIdentifier, ExtensionOIDs.basicConstraints };
      for (Asn1Oid extnType : extnTypes) {
        ExtensionControl control = extnControls.getControl(extnType);
        if (control == null) {
          msg.append("Mandatory extension ")
              .append(getExtensionIDDesc(extnType)).append(" is not set, ");
        } else {
          TripleState inRequest = control.inRequest();
          if (inRequest != TripleState.required && inRequest != TripleState.optional) {
            msg.append("Extension ").append(getExtensionIDDesc(extnType))
                .append(" must be allowed in the request, ");
          }
        }
      }
    }

    // BasicConstraints
    if (certLevel == CertLevel.RootCA) {
      Integer pathLen = certprofile.pathLenBasicConstraint();
      if (pathLen != null) {
        msg.append("Root CA must not set PathLen, ");
      }
    }

    if (certDomain == CertDomain.CABForumBR) {
      validateCABForumBR(certprofile, msg);
    }

    final int len = msg.length();
    if (len > 2) {
      msg.delete(len - 2, len);
      throw new CertprofileException(msg.toString());
    }

  } // method validate

  private static void validateCABForumBR(Certprofile certprofile, StringBuilder msg) {
    // Subject with only one entry in a RDN is allowed
    SubjectControl subjectCtl = certprofile.subjectControl();

    for (Asn1Oid m : subjectCtl.types()) {
      RdnControl ctl = subjectCtl.getControl(m);
      if (ctl.maxOccurs() > 1) {
        msg.append("multiple RDNs of the same type are not permitted, ");
      }
    }

    CertLevel certLevel = certprofile.certLevel();

    // validity
    if (certLevel == CertLevel.EndEntity) {
      Validity validity = certprofile.validity();
      if (validity.compareTo(maxCabEeValidity) > 0) {
        msg.append("validity exceeds the maximal validity of subscriber certificate, ");
      }
    }

    // Signature/hash algorithm
    List<SignAlgo> sigAlgos = certprofile.signatureAlgorithms();
    if (sigAlgos == null) {
      msg.append("signature algorithms not defined, ");
    } else {
      List<HashAlgo> allowedHashAlgos =
          Arrays.asList(HashAlgo.SHA256, HashAlgo.SHA384, HashAlgo.SHA512);
      for (SignAlgo signAlgo : sigAlgos) {
        HashAlgo hashAlgo = signAlgo.hashAlgo();
        if (!allowedHashAlgos.contains(hashAlgo)) {
          msg.append("unpermitted hash algorithm ").append(hashAlgo).append(", ");
        }
      }
    }

    // CRLDistributionPoints
    if (certLevel != CertLevel.RootCA) {
      // AuthorityInfoAccess*
      AuthorityInfoAccessControl aiaControl = certprofile.aiaControl();
      if (aiaControl != null) {
        if (!aiaControl.isIncludesOcsp()) {
          msg.append("access method id-ad-ocsp is not configured, ");
        }

        if (!aiaControl.isIncludesCaIssuers()) {
          msg.append("access method id-ad-caIssuers is not configured, ");
        }
      }
    }

    // Certificate Policies
    if (certLevel == CertLevel.SubCA || certLevel == CertLevel.EndEntity) {
      CertificatePolicies certPolicyValue = certprofile.certificatePolicies();
      if (certPolicyValue == null) {
        msg.append("CertificatePolicies is not configured, ");
      }
    }

    // ExtendedKeyUsage
    Set<ExtKeyUsageControl> ekuControls = certprofile.extendedKeyUsages();
    if (certLevel == CertLevel.EndEntity) {
      // ekuControls could not be null here.
      boolean xkuTlsServerRequired = false;
      boolean xkuTlsClientRequired = false;
      for (ExtKeyUsageControl m : ekuControls) {
        Asn1Oid oid = m.extKeyUsage();
        if (m.isRequired()) {
          if (KeyPurposeOIDs.id_kp_serverAuth.equals(oid)) {
            xkuTlsServerRequired = true;
          } else if (KeyPurposeOIDs.id_kp_clientAuth.equals(oid)) {
            xkuTlsClientRequired = true;
          }
        }

        if (!(KeyPurposeOIDs.id_kp_serverAuth.equals(oid)
            || KeyPurposeOIDs.id_kp_clientAuth.equals(oid)
            || KeyPurposeOIDs.id_kp_emailProtection.equals(oid))) {
          msg.append("extendedKeyUsage ").append(oid.getId()).append(" is not permitted, ");
        }
      }

      if (!(xkuTlsClientRequired | xkuTlsServerRequired)) {
        msg.append("none of ").append(KeyPurposeOIDs.id_kp_clientAuth).append(" and ")
          .append(KeyPurposeOIDs.id_kp_serverAuth).append(" is not configured, ");
      }
    } else {
      if (ekuControls != null) {
        for (ExtKeyUsageControl m : ekuControls) {
          if (m.extKeyUsage().equals(KeyPurposeOIDs.anyExtendedKeyUsage)) {
            msg.append(KeyPurposeOIDs.id_kp_clientAuth).append(" is not allowed, ");
          }
        }
      }
    }

  } // method validateCABForumBR

  private static String toString(Collection<Asn1Oid> oids) {
    if (oids == null) {
      return "null";
    }

    StringBuilder sb = new StringBuilder();
    sb.append("[");

    for (Asn1Oid oid : oids) {
      sb.append(getExtensionIDDesc(oid)).append(", ");
    }

    if (CollectionUtil.isNotEmpty(oids)) {
      int len = sb.length();
      sb.delete(len - 2, len);
    }
    sb.append("]");

    return sb.toString();
  } // method toString

  private static String getExtensionIDDesc(Asn1Oid oid) {
    return ExtensionID.ofOid(oid).mainAlias();
  }

}
