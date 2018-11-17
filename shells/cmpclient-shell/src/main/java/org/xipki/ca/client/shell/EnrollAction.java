/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.client.shell;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.xipki.cmpclient.EnrollCertRequest;
import org.xipki.cmpclient.EnrollCertResult;
import org.xipki.security.ExtensionExistence;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.SecurityFactory;
import org.xipki.security.exception.InvalidOidOrNameException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.completer.ExtKeyusageCompleter;
import org.xipki.shell.completer.ExtensionNameCompleter;
import org.xipki.shell.completer.HashAlgCompleter;
import org.xipki.shell.completer.KeyusageCompleter;
import org.xipki.util.DateUtil;
import org.xipki.util.IoUtil;
import org.xipki.util.ReqRespDebug;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class EnrollAction extends ClientAction {

  @Reference
  protected SecurityFactory securityFactory;

  @Option(name = "--subject", aliases = "-s", required = true,
      description = "subject to be requested")
  private String subject;

  @Option(name = "--profile", aliases = "-p", required = true, description = "certificate profile")
  private String profile;

  @Option(name = "--not-before", description = "notBefore, UTC time of format yyyyMMddHHmmss")
  private String notBeforeS;

  @Option(name = "--not-after", description = "notAfter, UTC time of format yyyyMMddHHmmss")
  private String notAfterS;

  @Option(name = "--ca",
      description = "CA name\n(required if the profile is supported by more than one CA)")
  @Completion(CaNameCompleter.class)
  private String caName;

  @Option(name = "--keyusage", multiValued = true, description = "keyusage")
  @Completion(KeyusageCompleter.class)
  private List<String> keyusages;

  @Option(name = "--ext-keyusage", multiValued = true,
      description = "extended keyusage (name or OID")
  @Completion(ExtKeyusageCompleter.class)
  private List<String> extkeyusages;

  @Option(name = "--subject-alt-name", multiValued = true, description = "subjectAltName")
  private List<String> subjectAltNames;

  @Option(name = "--subject-info-access", multiValued = true, description = "subjectInfoAccess")
  private List<String> subjectInfoAccesses;

  @Option(name = "--qc-eu-limit", multiValued = true,
      description = "QC EuLimitValue of format <currency>:<amount>:<exponent>.")
  private List<String> qcEuLimits;

  @Option(name = "--biometric-type", description = "Biometric type")
  private String biometricType;

  @Option(name = "--biometric-hash", description = "Biometric hash algorithm")
  @Completion(HashAlgCompleter.class)
  private String biometricHashAlgo;

  @Option(name = "--biometric-file", description = "Biometric hash algorithm")
  @Completion(FileCompleter.class)
  private String biometricFile;

  @Option(name = "--biometric-uri", description = "Biometric source data URI")
  private String biometricUri;

  @Option(name = "--need-extension", multiValued = true,
      description = "type (name or OID) of extension that must be contained in the certificate")
  @Completion(ExtensionNameCompleter.class)
  private List<String> needExtensionTypes;

  @Option(name = "--want-extension", multiValued = true,
      description = "type (name or OID) of extension that should be contained in the"
          + " certificate if possible")
  @Completion(ExtensionNameCompleter.class)
  private List<String> wantExtensionTypes;

  protected abstract SubjectPublicKeyInfo getPublicKey() throws Exception;

  protected abstract EnrollCertRequest.Entry buildEnrollCertRequestEntry(
      String id, String profile, CertRequest certRequest) throws Exception;

  protected abstract EnrollCertRequest.EnrollType getCmpReqType() throws Exception;

  protected EnrollCertResult enroll() throws Exception {
    // CHECKSTYLE:SKIP
    EnrollCertRequest.EnrollType type = getCmpReqType();

    if (caName != null) {
      caName = caName.toLowerCase();
    }

    if (needExtensionTypes != null) {
      needExtensionTypes = resolveExtensionTypes(needExtensionTypes);
    } else {
      needExtensionTypes = new LinkedList<>();
    }

    if (wantExtensionTypes != null) {
      wantExtensionTypes = resolveExtensionTypes(wantExtensionTypes);
    } else {
      wantExtensionTypes = new LinkedList<>();
    }

    if (extkeyusages != null) {
      List<String> list = new ArrayList<>(extkeyusages.size());
      for (String m : extkeyusages) {
        String id = ExtKeyusageCompleter.getIdForUsageName(m);
        if (id == null) {
          try {
            id = new ASN1ObjectIdentifier(m).getId();
          } catch (Exception ex) {
            throw new IllegalCmdParamException("invalid extended key usage " + m);
          }
        }
      }

      extkeyusages = list;
    }

    CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();

    X500Name x500Subject = new X500Name(subject);
    certTemplateBuilder.setSubject(x500Subject);

    SubjectPublicKeyInfo publicKey = getPublicKey();
    if (publicKey != null) {
      certTemplateBuilder.setPublicKey(getPublicKey());
    }

    if (StringUtil.isNotBlank(notBeforeS) || StringUtil.isNotBlank(notAfterS)) {
      Time notBefore = StringUtil.isNotBlank(notBeforeS)
          ? new Time(DateUtil.parseUtcTimeyyyyMMddhhmmss(notBeforeS)) : null;
      Time notAfter = StringUtil.isNotBlank(notAfterS)
          ? new Time(DateUtil.parseUtcTimeyyyyMMddhhmmss(notAfterS)) : null;
      OptionalValidity validity = new OptionalValidity(notBefore, notAfter);
      certTemplateBuilder.setValidity(validity);
    }

    // SubjectAltNames
    List<Extension> extensions = new LinkedList<>();
    if (isNotEmpty(subjectAltNames)) {
      extensions.add(X509Util.createExtnSubjectAltName(subjectAltNames, false));
      needExtensionTypes.add(Extension.subjectAlternativeName.getId());
    }

    // SubjectInfoAccess
    if (isNotEmpty(subjectInfoAccesses)) {
      extensions.add(X509Util.createExtnSubjectInfoAccess(subjectInfoAccesses, false));
      needExtensionTypes.add(Extension.subjectInfoAccess.getId());
    }

    // Keyusage
    if (isNotEmpty(keyusages)) {
      Set<KeyUsage> usages = new HashSet<>();
      for (String usage : keyusages) {
        usages.add(KeyUsage.getKeyUsage(usage));
      }
      org.bouncycastle.asn1.x509.KeyUsage extValue = X509Util.createKeyUsage(usages);
      ASN1ObjectIdentifier extType = Extension.keyUsage;
      extensions.add(new Extension(extType, false, extValue.getEncoded()));
      needExtensionTypes.add(extType.getId());
    }

    // ExtendedKeyusage
    if (isNotEmpty(extkeyusages)) {
      ExtendedKeyUsage extValue = X509Util.createExtendedUsage(
          textToAsn1ObjectIdentifers(extkeyusages));
      ASN1ObjectIdentifier extType = Extension.extendedKeyUsage;
      extensions.add(new Extension(extType, false, extValue.getEncoded()));
      needExtensionTypes.add(extType.getId());
    }

    // QcEuLimitValue
    if (isNotEmpty(qcEuLimits)) {
      ASN1EncodableVector vec = new ASN1EncodableVector();
      for (String m : qcEuLimits) {
        StringTokenizer st = new StringTokenizer(m, ":");
        try {
          String currencyS = st.nextToken();
          String amountS = st.nextToken();
          String exponentS = st.nextToken();

          Iso4217CurrencyCode currency;
          try {
            int intValue = Integer.parseInt(currencyS);
            currency = new Iso4217CurrencyCode(intValue);
          } catch (NumberFormatException ex) {
            currency = new Iso4217CurrencyCode(currencyS);
          }

          int amount = Integer.parseInt(amountS);
          int exponent = Integer.parseInt(exponentS);

          MonetaryValue monterayValue = new MonetaryValue(currency, amount, exponent);
          QCStatement statment = new QCStatement(
              ObjectIdentifiers.id_etsi_qcs_QcLimitValue, monterayValue);
          vec.add(statment);
        } catch (Exception ex) {
          throw new Exception("invalid qc-eu-limit '" + m + "'");
        }
      }

      ASN1ObjectIdentifier extType = Extension.qCStatements;
      ASN1Sequence extValue = new DERSequence(vec);
      extensions.add(new Extension(extType, false, extValue.getEncoded()));
      needExtensionTypes.add(extType.getId());
    }

    // biometricInfo
    if (biometricType != null && biometricHashAlgo != null && biometricFile != null) {
      TypeOfBiometricData objBiometricType = StringUtil.isNumber(biometricType)
          ? new TypeOfBiometricData(Integer.parseInt(biometricType))
          : new TypeOfBiometricData(new ASN1ObjectIdentifier(biometricType));

      ASN1ObjectIdentifier objBiometricHashAlgo = AlgorithmUtil.getHashAlg(biometricHashAlgo);
      byte[] biometricBytes = IoUtil.read(biometricFile);
      MessageDigest md = MessageDigest.getInstance(objBiometricHashAlgo.getId());
      md.reset();
      byte[] biometricDataHash = md.digest(biometricBytes);

      DERIA5String sourceDataUri = null;
      if (biometricUri != null) {
        sourceDataUri = new DERIA5String(biometricUri);
      }
      BiometricData biometricData = new BiometricData(objBiometricType,
          new AlgorithmIdentifier(objBiometricHashAlgo),
          new DEROctetString(biometricDataHash), sourceDataUri);

      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(biometricData);

      ASN1ObjectIdentifier extType = Extension.biometricInfo;
      ASN1Sequence extValue = new DERSequence(vec);
      extensions.add(new Extension(extType, false, extValue.getEncoded()));
      needExtensionTypes.add(extType.getId());
    } else if (biometricType == null && biometricHashAlgo == null && biometricFile == null) {
      // Do nothing
    } else {
      throw new Exception("either all of biometric triples (type, hash algo, file)"
          + " must be set or none of them should be set");
    }

    if (isNotEmpty(needExtensionTypes) || isNotEmpty(wantExtensionTypes)) {
      ExtensionExistence ee = new ExtensionExistence(textToAsn1ObjectIdentifers(needExtensionTypes),
          textToAsn1ObjectIdentifers(wantExtensionTypes));
      extensions.add(new Extension(ObjectIdentifiers.id_xipki_ext_cmpRequestExtensions, false,
                        ee.toASN1Primitive().getEncoded()));
    }

    if (isNotEmpty(extensions)) {
      Extensions asn1Extensions = new Extensions(extensions.toArray(new Extension[0]));
      certTemplateBuilder.setExtensions(asn1Extensions);
    }

    CertRequest certReq = new CertRequest(1, certTemplateBuilder.build(), null);

    EnrollCertRequest.Entry reqEntry = buildEnrollCertRequestEntry("id-1", profile, certReq);
    EnrollCertRequest request = new EnrollCertRequest(type);
    request.addRequestEntry(reqEntry);

    ReqRespDebug debug = getReqRespDebug();
    EnrollCertResult result;
    try {
      result = client.enrollCerts(caName, request, debug);
    } finally {
      saveRequestResponse(debug);
    }

    return result;
  } // method enroll

  static List<ASN1ObjectIdentifier> textToAsn1ObjectIdentifers(List<String> oidTexts)
      throws InvalidOidOrNameException {
    if (oidTexts == null) {
      return null;
    }

    List<ASN1ObjectIdentifier> ret = new ArrayList<>(oidTexts.size());
    for (String oidText : oidTexts) {
      if (oidText.isEmpty()) {
        continue;
      }

      ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(oidText);
      if (!ret.contains(oid)) {
        ret.add(oid);
      }
    }
    return ret;
  }

  static List<String> resolveExtensionTypes(List<String> types) throws IllegalCmdParamException {
    List<String> list = new ArrayList<>(types.size());
    for (String m : types) {
      String id = ExtensionNameCompleter.getIdForExtensionName(m);
      if (id == null) {
        try {
          id = new ASN1ObjectIdentifier(m).getId();
        } catch (Exception ex) {
          throw new IllegalCmdParamException("invalid extension type " + m);
        }
      }
    }
    return list;
  }

}
