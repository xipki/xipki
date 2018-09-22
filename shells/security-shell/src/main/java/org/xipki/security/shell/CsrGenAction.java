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

package org.xipki.security.shell;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.xipki.security.ConcurrentBagEntrySigner;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.ExtensionExistence;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.SignatureAlgoControl;
import org.xipki.security.exception.BadInputException;
import org.xipki.security.exception.InvalidOidOrNameException;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.completer.DerPemCompleter;
import org.xipki.shell.completer.ExtKeyusageCompleter;
import org.xipki.shell.completer.ExtensionNameCompleter;
import org.xipki.shell.completer.HashAlgCompleter;
import org.xipki.shell.completer.KeyusageCompleter;
import org.xipki.util.CollectionUtil;
import org.xipki.util.IoUtil;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class CsrGenAction extends SecurityAction {

  @Option(name = "--hash", description = "hash algorithm name")
  @Completion(HashAlgCompleter.class)
  protected String hashAlgo = "SHA256";

  @Option(name = "--subject-alt-name", multiValued = true, description = "subjectAltName")
  protected List<String> subjectAltNames;

  @Option(name = "--subject-info-access", multiValued = true, description = "subjectInfoAccess")
  protected List<String> subjectInfoAccesses;

  @Option(name = "--subject", aliases = "-s", required = true, description = "subject in the CSR")
  private String subject;

  @Option(name = "--rsa-mgf1",
      description = "whether to use the RSAPSS MGF1 for the POPO computation\n"
          + "(only applied to RSA key)")
  private Boolean rsaMgf1 = Boolean.FALSE;

  @Option(name = "--dsa-plain",
      description = "whether to use the Plain DSA for the POPO computation")
  private Boolean dsaPlain = Boolean.FALSE;

  @Option(name = "--gm",
      description = "whether to use the chinese GM algorithm for the POPO computation\n"
          + "(only applied to EC key with GM curves)")
  private Boolean gm = Boolean.FALSE;

  @Option(name = "--outform", description = "output format of the CSR")
  @Completion(DerPemCompleter.class)
  protected String outform = "der";

  @Option(name = "--out", aliases = "-o", required = true, description = "CSR file")
  @Completion(FileCompleter.class)
  private String outputFilename;

  @Option(name = "--challenge-password", aliases = "-c", description = "challenge password")
  private String challengePassword;

  @Option(name = "--keyusage", multiValued = true, description = "keyusage")
  @Completion(KeyusageCompleter.class)
  private List<String> keyusages;

  @Option(name = "--ext-keyusage", multiValued = true,
      description = "extended keyusage (name or OID)")
  @Completion(ExtKeyusageCompleter.class)
  private List<String> extkeyusages;

  @Option(name = "--qc-eu-limit", multiValued = true,
      description = "QC EuLimitValue of format <currency>:<amount>:<exponent>")
  private List<String> qcEuLimits;

  @Option(name = "--biometric-type", description = "Biometric type")
  private String biometricType;

  @Option(name = "--biometric-hash", description = "Biometric hash algorithm")
  @Completion(HashAlgCompleter.class)
  private String biometricHashAlgo;

  @Option(name = "--biometric-file", description = "Biometric hash algorithm")
  private String biometricFile;

  @Option(name = "--biometric-uri", description = "Biometric sourcedata URI")
  @Completion(FileCompleter.class)
  private String biometricUri;

  @Option(name = "--need-extension", multiValued = true,
      description = "types (name or OID) of extension that must be contained in the certificate")
  @Completion(ExtensionNameCompleter.class)
  private List<String> needExtensionTypes;

  @Option(name = "--want-extension", multiValued = true,
      description = "types (name or OID) of extension that should be contained in the certificate "
                    + "if possible")
  @Completion(ExtensionNameCompleter.class)
  private List<String> wantExtensionTypes;

  /**
   * Gets the signer for the give signatureAlgoControl.
   * @param signatureAlgoControl
   *          The signature control. Must not be {@code null}.
   * @return the signer
   */
  protected abstract ConcurrentContentSigner getSigner(
       SignatureAlgoControl signatureAlgoControl) throws Exception;

  @Override
  protected Object execute0() throws Exception {
    hashAlgo = hashAlgo.trim().toUpperCase();
    if (hashAlgo.indexOf('-') != -1) {
      hashAlgo = hashAlgo.replaceAll("-", "");
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

    // SubjectAltNames
    List<Extension> extensions = new LinkedList<>();

    ASN1OctetString extnValue = createExtnValueSubjectAltName();
    if (extnValue != null) {
      ASN1ObjectIdentifier oid = Extension.subjectAlternativeName;
      extensions.add(new Extension(oid, false, extnValue));
      needExtensionTypes.add(oid.getId());
    }

    // SubjectInfoAccess
    extnValue = createExtnValueSubjectInfoAccess();
    if (extnValue != null) {
      ASN1ObjectIdentifier oid = Extension.subjectInfoAccess;
      extensions.add(new Extension(oid, false, extnValue));
      needExtensionTypes.add(oid.getId());
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
      TypeOfBiometricData tmpBiometricType = StringUtil.isNumber(biometricType)
          ? new TypeOfBiometricData(Integer.parseInt(biometricType))
          : new TypeOfBiometricData(new ASN1ObjectIdentifier(biometricType));

      ASN1ObjectIdentifier tmpBiometricHashAlgo = AlgorithmUtil.getHashAlg(biometricHashAlgo);
      byte[] biometricBytes = IoUtil.read(biometricFile);
      MessageDigest md = MessageDigest.getInstance(tmpBiometricHashAlgo.getId());
      md.reset();
      byte[] tmpBiometricDataHash = md.digest(biometricBytes);

      DERIA5String tmpSourceDataUri = null;
      if (biometricUri != null) {
        tmpSourceDataUri = new DERIA5String(biometricUri);
      }
      BiometricData biometricData = new BiometricData(tmpBiometricType,
          new AlgorithmIdentifier(tmpBiometricHashAlgo),
          new DEROctetString(tmpBiometricDataHash), tmpSourceDataUri);

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

    for (Extension addExt : getAdditionalExtensions()) {
      extensions.add(addExt);
    }

    needExtensionTypes.addAll(getAdditionalNeedExtensionTypes());
    wantExtensionTypes.addAll(getAdditionalWantExtensionTypes());

    if (isNotEmpty(needExtensionTypes) || isNotEmpty(wantExtensionTypes)) {
      ExtensionExistence ee = new ExtensionExistence(textToAsn1ObjectIdentifers(needExtensionTypes),
          textToAsn1ObjectIdentifers(wantExtensionTypes));
      extensions.add(new Extension(ObjectIdentifiers.id_xipki_ext_cmpRequestExtensions, false,
          ee.toASN1Primitive().getEncoded()));
    }

    ConcurrentContentSigner signer = getSigner(new SignatureAlgoControl(rsaMgf1, dsaPlain, gm));

    Map<ASN1ObjectIdentifier, ASN1Encodable> attributes = new HashMap<>();
    if (CollectionUtil.isNonEmpty(extensions)) {
      attributes.put(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
          new Extensions(extensions.toArray(new Extension[0])));
    }

    if (StringUtil.isNotBlank(challengePassword)) {
      attributes.put(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
          new DERPrintableString(challengePassword));
    }

    SubjectPublicKeyInfo subjectPublicKeyInfo;
    if (signer.getCertificate() != null) {
      Certificate cert = Certificate.getInstance(signer.getCertificate().getEncoded());
      subjectPublicKeyInfo = cert.getSubjectPublicKeyInfo();
    } else {
      subjectPublicKeyInfo = KeyUtil.createSubjectPublicKeyInfo(signer.getPublicKey());
    }

    X500Name subjectDn = getSubject(subject);
    PKCS10CertificationRequest csr = generateRequest(signer, subjectPublicKeyInfo, subjectDn,
        attributes);

    saveVerbose("saved CSR to file", outputFilename, encodeCsr(csr.getEncoded(), outform));
    return null;
  } // method execute0

  protected X500Name getSubject(String subjectText) {
    ParamUtil.requireNonBlank("subjectText", subjectText);
    return new X500Name(subjectText);
  }

  protected List<String> getAdditionalNeedExtensionTypes() {
    return Collections.emptyList();
  }

  protected List<String> getAdditionalWantExtensionTypes() {
    return Collections.emptyList();
  }

  protected List<Extension> getAdditionalExtensions() throws BadInputException {
    return Collections.emptyList();
  }

  protected ASN1OctetString createExtnValueSubjectAltName() throws BadInputException {
    return isEmpty(subjectAltNames) ? null
        : X509Util.createExtnSubjectAltName(subjectAltNames, false).getExtnValue();
  }

  protected ASN1OctetString createExtnValueSubjectInfoAccess() throws BadInputException {
    return isEmpty(subjectInfoAccesses) ? null
        : X509Util.createExtnSubjectInfoAccess(subjectInfoAccesses, false).getExtnValue();
  }

  private static List<ASN1ObjectIdentifier> textToAsn1ObjectIdentifers(
      List<String> oidTexts) throws InvalidOidOrNameException {
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

  private PKCS10CertificationRequest generateRequest(ConcurrentContentSigner signer,
      SubjectPublicKeyInfo subjectPublicKeyInfo, X500Name subjectDn,
      Map<ASN1ObjectIdentifier, ASN1Encodable> attributes) throws XiSecurityException {
    ParamUtil.requireNonNull("signer", signer);
    ParamUtil.requireNonNull("subjectPublicKeyInfo", subjectPublicKeyInfo);
    ParamUtil.requireNonNull("subjectDn", subjectDn);
    PKCS10CertificationRequestBuilder csrBuilder =
        new PKCS10CertificationRequestBuilder(subjectDn, subjectPublicKeyInfo);
    if (CollectionUtil.isNonEmpty(attributes)) {
      for (ASN1ObjectIdentifier attrType : attributes.keySet()) {
        csrBuilder.addAttribute(attrType, attributes.get(attrType));
      }
    }

    ConcurrentBagEntrySigner signer0;
    try {
      signer0 = signer.borrowSigner();
    } catch (NoIdleSignerException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }

    try {
      return csrBuilder.build(signer0.value());
    } finally {
      signer.requiteSigner(signer0);
    }
  }

  private List<String> resolveExtensionTypes(List<String> types) throws IllegalCmdParamException {
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
