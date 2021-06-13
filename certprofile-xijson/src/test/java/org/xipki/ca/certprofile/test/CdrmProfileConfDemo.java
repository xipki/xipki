/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.certprofile.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.Certprofile.CertLevel;
import org.xipki.ca.api.profile.SubjectKeyIdentifierControl;
import org.xipki.ca.certprofile.xijson.conf.*;
import org.xipki.ca.certprofile.xijson.conf.Subject.RdnType;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.DN;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.util.AlgorithmUtil;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static org.xipki.ca.certprofile.test.ProfileConfBuilder.*;

/**
 * Demo the creation of xijson configuration.
 *
 * @author Lijun Liao
 */

public class CdrmProfileConfDemo extends ExtensionConfBuilder {

  public static void main(String[] args) {
    try {
      certprofileRootCa("certprofile-cdrm-rootca.json");

      certprofileClientSubCa("certprofile-cdrm-client-subca.json");
      certprofileClient("certprofile-cdrm-client.json");

      certprofileServerSubCa("certprofile-cdrm-server-subca.json");
      certprofileOcsp("certprofile-cdrm-ocsp.json");
      certprofileContentEncryption("certprofile-cdrm-contentencryption.json");
      certprofileKeyGateway("certprofile-cdrm-keygateway.json");
      certprofileKeyManagent("certprofile-cdrm-keymanagement.json");
      certprofileServer("certprofile-cdrm-server.json");
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  } // method main

  private static SubjectKeyIdentifierControl createSubjectKeyIdControl() {
    SubjectKeyIdentifierControl control = new SubjectKeyIdentifierControl();
    control.setHashAlgo("SM3");
    control.setMethod(SubjectKeyIdentifierControl.SubjectKeyIdentifierMethod.METHOD_1);
    return control;
  }

  private static void certprofileRootCa(String destFilename) {
    X509ProfileType profile = getBaseProfile("China DRM Root CA", CertLevel.RootCA, "50y");

    // TODO: set serial number size
    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.CN, 1, 1));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign},
            null));

    // SubjectKeyIdentifier
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    last(list).setSubjectKeyIdentifier(createSubjectKeyIdControl());

    marshall(profile, destFilename, true);
  } // method certprofileRootCa

  private static void createCertprofileSubCa(String destFilename, String desc) {
    X509ProfileType profile = getBaseProfile(desc, CertLevel.SubCA, "99y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.CN, 1, 1));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - basicConstraints
    list.add(createExtension(Extension.basicConstraints, true, true));
    last(list).setBasicConstrains(createBasicConstraints(0));

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.keyCertSign, KeyUsage.cRLSign},
            null));

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // SubjectKeyIdentifier
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    last(list).setSubjectKeyIdentifier(createSubjectKeyIdControl());

    marshall(profile, destFilename, true);
  } // method certprofileServerSubCa

  private static void certprofileServerSubCa(String destFilename) {
    createCertprofileSubCa(destFilename, "China DRM Server CA");
  }

  private static void certprofileOcsp(String destFilename) {
    String desc = "China DRM OCSP";
    X509ProfileType profile = getBaseProfile(desc, CertLevel.EndEntity, "3m");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 1, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.CN, 1, 1));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - basicConstraints
    // none

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.digitalSignature},
            null));

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // SubjectKeyIdentifier
    list.add(createExtension(Extension.subjectKeyIdentifier, true, false));
    last(list).setSubjectKeyIdentifier(createSubjectKeyIdControl());

    // Extensions - extendedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, true));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
            new ASN1ObjectIdentifier[]{ObjectIdentifiers.XKU.id_kp_ocspSigning},
            null));

    // Extensions - OCSP NoCheck
    list.add(createExtension(
            Extn.id_extension_pkix_ocsp_nocheck, true, false, null));

    marshall(profile, destFilename, true);
  } // method certprofileOcsp

  private static void certprofileServer(String destFilename) {
    createCertprofileServer(destFilename, "China DRM Server", "1.2.156.112560.7");
  }

  private static void certprofileKeyManagent(String destFilename) {
    createCertprofileServer(destFilename, "China DRM Key Management", "1.2.156.112560.23");
  } // method certprofileKeyManagent

  private static void certprofileKeyGateway(String destFilename) {
    createCertprofileServer(destFilename, "China DRM Key Gateway", "1.2.156.112560.24");
  }

  private static void certprofileContentEncryption(String destFilename) {
    createCertprofileServer(destFilename, "China DRM Content Encryption", "1.2.156.112560.22");
  }

  private static void createCertprofileServer(
          String destFilename, String desc, String extKeyUsage) {
    X509ProfileType profile = getBaseProfile(desc, CertLevel.EndEntity, "5y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 0, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.CN, 0, 1));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - basicConstraints
    // none

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(new KeyUsage[]{KeyUsage.digitalSignature},
            null));

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // SubjectKeyIdentifier
    // none

    // Extensions - extendedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, true));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
            new ASN1ObjectIdentifier[]{new ASN1ObjectIdentifier(extKeyUsage)},
            null));

    marshall(profile, destFilename, true);
  } // method createCertprofileServer

  private static void certprofileClientSubCa(String destFilename) {
    createCertprofileSubCa(destFilename, "China DRM Client CA");
  }

  private static void certprofileClient(
          String destFilename) {
    X509ProfileType profile = getBaseProfile("China DRM Device", CertLevel.EndEntity, "20y");

    // Subject
    Subject subject = profile.getSubject();

    List<RdnType> rdnControls = subject.getRdns();
    rdnControls.add(createRdn(DN.C, 0, 1));
    rdnControls.add(createRdn(DN.O, 1, 1));
    rdnControls.add(createRdn(DN.OU, 0, 1));
    rdnControls.add(createRdn(DN.SN, 1, 1, null, null, null, null, ":SM3(SubjectPublicKeyInfo"));
    rdnControls.add(createRdn(DN.CN, 1, 1));

    // Extensions
    List<ExtensionType> list = profile.getExtensions();

    // Extensions - basicConstraints
    // none

    // Extensions - keyUsage
    list.add(createExtension(Extension.keyUsage, true, true));
    last(list).setKeyUsage(createKeyUsage(
            new KeyUsage[]{KeyUsage.digitalSignature, KeyUsage.keyEncipherment},
            null));

    // Extensions - AuthorityKeyIdentifier
    list.add(createExtension(Extension.authorityKeyIdentifier, true, false));

    // SubjectKeyIdentifier
    // none

    // Extensions - extendedKeyUsage
    list.add(createExtension(Extension.extendedKeyUsage, true, true));
    last(list).setExtendedKeyUsage(createExtendedKeyUsage(
            new ASN1ObjectIdentifier[]{new ASN1ObjectIdentifier("1.2.156.112560.8")},
            null));

    marshall(profile, destFilename, true);
  } // method createCertprofileServer

  private static X509ProfileType getBaseProfile(
          String description,
          CertLevel certLevel,
          String validity) {
    X509ProfileType profile = new X509ProfileType();

    profile.setMetadata(createDescription(description));

    profile.setCertLevel(certLevel);
    profile.setMaxSize(1000);
    profile.setVersion(Certprofile.X509CertVersion.v3);
    profile.setValidity(validity);
    profile.setNotBeforeTime("current");

    profile.setSerialNumberInReq(false);

    if (certLevel == CertLevel.EndEntity) {
      profile.setKeypairGeneration(new KeypairGenerationType());
      profile.getKeypairGeneration().setInheritCA(true);
    }

    // SignatureAlgorithms
    List<String> algos = new LinkedList<>();
    profile.setSignatureAlgorithms(algos);
    algos.add("SM3withSM2");

    // Subject
    Subject subject = new Subject();
    profile.setSubject(subject);
    subject.setKeepRdnOrder(false);

    // Key
    profile.setKeyAlgorithms(createKeyAlgorithms());

    return profile;
  } // method getBaseProfile

  private static List<AlgorithmType> createKeyAlgorithms() {
    List<AlgorithmType> list = new LinkedList<>();

    // EC
    AlgorithmType alg = new AlgorithmType();
    list.add(alg);

    alg.getAlgorithms().add(createOidType(X9ObjectIdentifiers.id_ecPublicKey, "EC"));
    alg.setParameters(new KeyParametersType());

    KeyParametersType.EcParametersType ecParams = new KeyParametersType.EcParametersType();
    alg.getParameters().setEc(ecParams);

    List<Describable.DescribableOid> curves = new LinkedList<>();
    ecParams.setCurves(curves);

    ASN1ObjectIdentifier curveId = GMObjectIdentifiers.sm2p256v1;
    String name = AlgorithmUtil.getCurveName(curveId);
    curves.add(createOidType(curveId, name));

    ecParams.setPointEncodings(Collections.singletonList(((byte) 4)));

    return list;
  } // method createKeyAlgorithms
}
