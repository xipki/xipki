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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.apache.karaf.shell.support.completers.StringsCompleter;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xipki.cmpclient.CertIdOrError;
import org.xipki.cmpclient.CmpClient;
import org.xipki.cmpclient.CmpClientException;
import org.xipki.cmpclient.EnrollCertRequest;
import org.xipki.cmpclient.EnrollCertResult;
import org.xipki.cmpclient.PkiErrorException;
import org.xipki.cmpclient.EnrollCertRequest.EnrollType;
import org.xipki.cmpclient.EnrollCertResult.CertifiedKeyPairOrError;
import org.xipki.security.ConcurrentBagEntrySigner;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.CrlReason;
import org.xipki.security.ExtensionExistence;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignatureAlgoControl;
import org.xipki.security.SignerConf;
import org.xipki.security.cmp.PkiStatusInfo;
import org.xipki.security.exception.InvalidOidOrNameException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.Args;
import org.xipki.util.ConfPairs;
import org.xipki.util.DateUtil;
import org.xipki.util.HealthCheckResult;
import org.xipki.util.Hex;
import org.xipki.util.IoUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.ReqRespDebug;
import org.xipki.util.StringUtil;
import org.xipki.util.ReqRespDebug.ReqRespPair;

import com.alibaba.fastjson.JSON;

/**
 * TODO.
 * @author Lijun Liao
 *
 */
public class Actions {

  public abstract static class ClientAction extends XiAction {

    @Reference
    protected CmpClient client;

    @Option(name = "--req-out", description = "where to save the request")
    @Completion(FileCompleter.class)
    private String reqout;

    @Option(name = "--resp-out", description = "where to save the response")
    @Completion(FileCompleter.class)
    private String respout;

    protected ReqRespDebug getReqRespDebug() {
      boolean saveReq = isNotBlank(reqout);
      boolean saveResp = isNotBlank(respout);
      if (saveReq || saveResp) {
        return new ReqRespDebug(saveReq, saveResp);
      }
      return null;
    }

    protected void saveRequestResponse(ReqRespDebug debug) {
      boolean saveReq = isNotBlank(reqout);
      boolean saveResp = isNotBlank(respout);
      if (!saveReq && !saveResp) {
        return;
      }

      if (debug == null || debug.size() == 0) {
        return;
      }

      final int n = debug.size();
      for (int i = 0; i < n; i++) {
        ReqRespPair reqResp = debug.get(i);
        if (saveReq) {
          byte[] bytes = reqResp.getRequest();
          if (bytes != null) {
            String fn = (n == 1) ? reqout : appendIndex(reqout, i);
            try {
              IoUtil.save(fn, bytes);
            } catch (IOException ex) {
              System.err.println("IOException: " + ex.getMessage());
            }
          }
        }

        if (saveResp) {
          byte[] bytes = reqResp.getResponse();
          if (bytes != null) {
            String fn = (n == 1) ? respout : appendIndex(respout, i);
            try {
              IoUtil.save(fn, bytes);
            } catch (IOException ex) {
              System.err.println("IOException: " + ex.getMessage());
            }
          }
        }
      }
    } // method saveRequestResponse

    private static String appendIndex(String filename, int index) {
      int idx = filename.lastIndexOf('.');
      if (idx == -1 || idx == filename.length() - 1) {
        return filename + "-" + index;
      }

      StringBuilder sb = new StringBuilder(filename);
      sb.insert(idx, index);
      sb.insert(idx, '-');
      return sb.toString();
    }

  }

  @Command(scope = "xi", name = "cmp-init", description = "initialize CMP client")
  @Service
  public static class CmpInit extends ClientAction {

    @Override
    protected Object execute0() throws Exception {
      boolean succ = client.init();
      if (succ) {
        println("CA client initialized successfully");
      } else {
        println("CA client initialization failed");
      }
      return null;
    }

  }

  public abstract static class CrlAction extends ClientAction {

    @Option(name = "--ca", description = "CA name\n(required if multiple CAs are configured)")
    @Completion(CmpClientCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(name = "--outform", description = "output format of the CRL")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the CRL")
    @Completion(FileCompleter.class)
    protected String outFile;

    protected abstract X509CRL retrieveCrl() throws CmpClientException, PkiErrorException;

    @Override
    protected Object execute0() throws Exception {
      if (caName != null) {
        caName = caName.toLowerCase();
      }

      Set<String> caNames = client.getCaNames();
      if (isEmpty(caNames)) {
        throw new CmdFailure("no CA is configured");
      }

      if (caName != null && !caNames.contains(caName)) {
        throw new IllegalCmdParamException("CA " + caName
            + " is not within the configured CAs " + caNames);
      }

      if (caName == null) {
        if (caNames.size() == 1) {
          caName = caNames.iterator().next();
        } else {
          throw new IllegalCmdParamException("no CA is specified, one of " + caNames
              + " is required");
        }
      }

      X509CRL crl = null;
      try {
        crl = retrieveCrl();
      } catch (PkiErrorException ex) {
        throw new CmdFailure("received no CRL from server: " + ex.getMessage());
      }

      if (crl == null) {
        throw new CmdFailure("received no CRL from server");
      }

      saveVerbose("saved CRL to file", outFile, encodeCrl(crl.getEncoded(), outform));
      return null;
    } // method execute0

  }

  @Command(scope = "xi", name = "cmp-csr-enroll", description = "enroll certificate via CSR")
  @Service
  public static class CmpCsrEnroll extends ClientAction {

    @Option(name = "--csr", required = true, description = "CSR file")
    @Completion(FileCompleter.class)
    private String csrFile;

    @Option(name = "--profile", aliases = "-p", required = true,
        description = "certificate profile")
    private String profile;

    @Option(name = "--not-before", description = "notBefore, UTC time of format yyyyMMddHHmmss")
    private String notBeforeS;

    @Option(name = "--not-after", description = "notAfter, UTC time of format yyyyMMddHHmmss")
    private String notAfterS;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Option(name = "--ca",
        description = "CA name\n(required if the profile is supported by more than one CA)")
    @Completion(CmpClientCompleters.CaNameCompleter.class)
    private String caName;

    @Override
    protected Object execute0() throws Exception {
      if (caName != null) {
        caName = caName.toLowerCase();
      }

      CertificationRequest csr = X509Util.parseCsr(new File(csrFile));

      Date notBefore = StringUtil.isNotBlank(notBeforeS)
          ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notBeforeS) : null;
      Date notAfter = StringUtil.isNotBlank(notAfterS)
            ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notAfterS) : null;
      EnrollCertResult result;
      ReqRespDebug debug = getReqRespDebug();
      try {
        result = client.enrollCert(caName, csr, profile, notBefore, notAfter, debug);
      } finally {
        saveRequestResponse(debug);
      }

      X509Certificate cert = null;
      if (result != null) {
        String id = result.getAllIds().iterator().next();
        CertifiedKeyPairOrError certOrError = result.getCertOrError(id);
        cert = (X509Certificate) certOrError.getCertificate();
      }

      if (cert == null) {
        throw new CmdFailure("no certificate received from the server");
      }

      saveVerbose("certificate saved to file", outputFile, encodeCert(cert.getEncoded(), outform));
      return null;
    }

  }

  public abstract static class EnrollAction extends ClientAction {

    @Reference
    protected SecurityFactory securityFactory;

    @Option(name = "--subject", aliases = "-s", required = true,
        description = "subject to be requested")
    private String subject;

    @Option(name = "--profile", aliases = "-p", required = true,
        description = "certificate profile")
    private String profile;

    @Option(name = "--not-before", description = "notBefore, UTC time of format yyyyMMddHHmmss")
    private String notBeforeS;

    @Option(name = "--not-after", description = "notAfter, UTC time of format yyyyMMddHHmmss")
    private String notAfterS;

    @Option(name = "--ca",
        description = "CA name\n(required if the profile is supported by more than one CA)")
    @Completion(CmpClientCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--keyusage", multiValued = true, description = "keyusage")
    @Completion(Completers.KeyusageCompleter.class)
    private List<String> keyusages;

    @Option(name = "--ext-keyusage", multiValued = true,
        description = "extended keyusage (name or OID")
    @Completion(Completers.ExtKeyusageCompleter.class)
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
    @Completion(Completers.HashAlgCompleter.class)
    private String biometricHashAlgo;

    @Option(name = "--biometric-file", description = "Biometric hash algorithm")
    @Completion(FileCompleter.class)
    private String biometricFile;

    @Option(name = "--biometric-uri", description = "Biometric source data URI")
    private String biometricUri;

    @Option(name = "--need-extension", multiValued = true,
        description = "type (name or OID) of extension that must be contained in the certificate")
    @Completion(Completers.ExtensionNameCompleter.class)
    private List<String> needExtensionTypes;

    @Option(name = "--want-extension", multiValued = true,
        description = "type (name or OID) of extension that should be contained in the"
            + " certificate if possible")
    @Completion(Completers.ExtensionNameCompleter.class)
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
          String id = Completers.ExtKeyusageCompleter.getIdForUsageName(m);
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
        ExtensionExistence ee = new ExtensionExistence(
            textToAsn1ObjectIdentifers(needExtensionTypes),
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
        String id = Completers.ExtensionNameCompleter.getIdForExtensionName(m);
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

  public abstract static class EnrollCertAction extends EnrollAction {

    @Option(name = "--cmpreq-type",
        description = "CMP request type (ir for Initialization Request,\n"
            + "cr for Certification Request, and ccr for Cross-Certification Request)")
    @Completion(value = StringsCompleter.class, values = {"ir", "cr", "ccr"})
    private String cmpreqType = "cr";

    @Option(name = "--hash", description = "hash algorithm name for the POPO computation")
    protected String hashAlgo = "SHA256";

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Option(name = "--rsa-mgf1",
        description = "whether to use the RSAPSS MGF1 for the POPO computation\n"
            + "(only applied to RSA key)")
    private Boolean rsaMgf1 = Boolean.FALSE;

    @Option(name = "--dsa-plain",
        description = "whether to use the Plain DSA for the POPO computation\n"
            + "(only applied to DSA and ECDSA key)")
    private Boolean dsaPlain = Boolean.FALSE;

    @Option(name = "--gm",
        description = "whether to use the chinese GM algorithm for the POPO computation\n"
            + "(only applied to EC key with GM curves)")
    private Boolean gm = Boolean.FALSE;

    protected SignatureAlgoControl getSignatureAlgoControl() {
      return new SignatureAlgoControl(rsaMgf1, dsaPlain, gm);
    }

    /**
     * TODO.
     * @param signatureAlgoControl
     *          Signature algorithm control. Must not be {@code null}.
     */
    protected abstract ConcurrentContentSigner getSigner() throws ObjectCreationException;

    @Override
    protected SubjectPublicKeyInfo getPublicKey() throws Exception {
      ConcurrentContentSigner signer = getSigner();
      X509CertificateHolder ssCert = signer.getBcCertificate();
      return ssCert.getSubjectPublicKeyInfo();
    }

    @Override
    protected EnrollCertRequest.Entry buildEnrollCertRequestEntry(String id, String profile,
        CertRequest certRequest) throws Exception {
      ConcurrentContentSigner signer = getSigner();

      ProofOfPossessionSigningKeyBuilder popoBuilder =
          new ProofOfPossessionSigningKeyBuilder(certRequest);
      ConcurrentBagEntrySigner signer0 = signer.borrowSigner();
      POPOSigningKey popoSk;
      try {
        popoSk = popoBuilder.build(signer0.value());
      } finally {
        signer.requiteSigner(signer0);
      }

      ProofOfPossession popo = new ProofOfPossession(popoSk);
      return new EnrollCertRequest.Entry(id, profile, certRequest, popo);
    }

    @Override
    protected Object execute0() throws Exception {
      EnrollCertResult result = enroll();

      X509Certificate cert = null;
      if (result != null) {
        String id = result.getAllIds().iterator().next();
        CertifiedKeyPairOrError certOrError = result.getCertOrError(id);
        cert = (X509Certificate) certOrError.getCertificate();
      }

      if (cert == null) {
        throw new CmdFailure("no certificate received from the server");
      }

      saveVerbose("saved certificate to file", outputFile, encodeCert(cert.getEncoded(), outform));

      return null;
    } // method execute0

    @Override
    protected EnrollType getCmpReqType() throws Exception {
      if ("cr".equalsIgnoreCase(cmpreqType)) {
        return EnrollCertRequest.EnrollType.CERT_REQ;
      } else if ("ir".equalsIgnoreCase(cmpreqType)) {
        return EnrollCertRequest.EnrollType.INIT_REQ;
      } else if ("ccr".equalsIgnoreCase(cmpreqType)) {
        return EnrollCertRequest.EnrollType.CROSS_CERT_REQ;
      } else {
        throw new IllegalCmdParamException("invalid cmpreq-type " + cmpreqType);
      }
    }

  }

  @Command(scope = "xi", name = "cmp-enroll-cagenkey",
      description = "enroll certificate (keypair will be generated by the CA)")
  @Service
  public static class CmpEnrollCagenkey extends EnrollAction {

    @Option(name = "--cmpreq-type",
        description = "CMP request type (ir for Initialization Request,\n"
            + "and cr for Certification Request)")
    @Completion(value = StringsCompleter.class, values = {"ir", "cr"})
    private String cmpreqType = "cr";

    @Option(name = "--cert-outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String certOutform = "der";

    @Option(name = "--cert-out", description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String certOutputFile;

    @Option(name = "--p12-out", required = true, description = "where to save the PKCS#12 keystore")
    @Completion(FileCompleter.class)
    private String p12OutputFile;

    @Option(name = "--password", description = "password of the PKCS#12 file")
    private String password;

    @Override
    protected SubjectPublicKeyInfo getPublicKey() throws Exception {
      return null;
    }

    @Override
    protected EnrollCertRequest.Entry buildEnrollCertRequestEntry(String id, String profile,
        CertRequest certRequest) throws Exception {
      final boolean caGenKeypair = true;
      final boolean kup = false;
      return new EnrollCertRequest.Entry("id-1", profile, certRequest, null, caGenKeypair, kup);
    }

    @Override
    protected Object execute0() throws Exception {
      EnrollCertResult result = enroll();

      X509Certificate cert = null;
      PrivateKeyInfo privateKeyInfo = null;
      if (result != null) {
        String id = result.getAllIds().iterator().next();
        CertifiedKeyPairOrError certOrError = result.getCertOrError(id);
        cert = (X509Certificate) certOrError.getCertificate();
        privateKeyInfo = certOrError.getPrivateKeyInfo();
      }

      if (cert == null) {
        throw new CmdFailure("no certificate received from the server");
      }

      if (privateKeyInfo == null) {
        throw new CmdFailure("no private key received from the server");
      }

      if (StringUtil.isNotBlank(certOutputFile)) {
        saveVerbose("saved certificate to file", certOutputFile,
            encodeCert(cert.getEncoded(), certOutform));
      }

      PrivateKey privateKey = BouncyCastleProvider.getPrivateKey(privateKeyInfo);

      KeyStore ks = KeyStore.getInstance("PKCS12");
      char[] pwd = getPassword();
      ks.load(null, pwd);
      ks.setKeyEntry("main", privateKey, pwd, new Certificate[] {cert});
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      ks.store(bout, pwd);
      saveVerbose("saved key to file", p12OutputFile, bout.toByteArray());

      return null;
    } // method execute0

    @Override
    protected EnrollType getCmpReqType() throws Exception {
      if ("cr".equalsIgnoreCase(cmpreqType)) {
        return EnrollCertRequest.EnrollType.CERT_REQ;
      } else if ("ir".equalsIgnoreCase(cmpreqType)) {
        return EnrollCertRequest.EnrollType.INIT_REQ;
      } else {
        throw new IllegalCmdParamException("invalid cmpreq-type " + cmpreqType);
      }
    }

    private char[] getPassword() throws IOException {
      char[] pwdInChar = readPasswordIfNotSet(password);
      if (pwdInChar != null) {
        password = new String(pwdInChar);
      }
      return pwdInChar;
    }

  }

  @Command(scope = "xi", name = "cmp-gencrl", description = "generate CRL")
  @Service
  public static class CmpGencrl extends CrlAction {

    @Override
    protected X509CRL retrieveCrl() throws CmpClientException, PkiErrorException {
      ReqRespDebug debug = getReqRespDebug();
      try {
        return client.generateCrl(caName, debug);
      } finally {
        saveRequestResponse(debug);
      }
    }

  }

  @Command(scope = "xi", name = "cmp-cacert", description = "get CA certificate")
  @Service
  public static class CmpCacert extends ClientAction {

    @Option(name = "--ca", description = "CA name\n(required if multiple CAs are configured)")
    @Completion(CmpClientCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the CA certificate")
    @Completion(FileCompleter.class)
    private String outFile;

    @Override
    protected Object execute0() throws Exception {
      if (caName != null) {
        caName = caName.toLowerCase();
      }

      Set<String> caNames = client.getCaNames();
      if (isEmpty(caNames)) {
        throw new CmdFailure("no CA is configured");
      }

      if (caName != null && !caNames.contains(caName)) {
        throw new IllegalCmdParamException("CA " + caName
            + " is not within the configured CAs " + caNames);
      }

      if (caName == null) {
        if (caNames.size() == 1) {
          caName = caNames.iterator().next();
        } else {
          throw new IllegalCmdParamException("no CA is specified, one of " + caNames
              + " is required");
        }
      }

      Certificate caCert;
      try {
        caCert = client.getCaCert(caName);
      } catch (Exception ex) {
        throw new CmdFailure("Error while retrieving CA certificate: " + ex.getMessage());
      }

      if (caCert == null) {
        throw new CmdFailure("received no CA certificate");
      }

      saveVerbose(
          "saved CA certificate to file", outFile, encodeCert(caCert.getEncoded(), outform));
      return null;
    } // method execute0

  }

  @Command(scope = "xi", name = "cmp-getcrl", description = "download CRL")
  @Service
  public static class CmpGetcrl extends CrlAction {

    @Option(name = "--with-basecrl",
        description = "whether to retrieve the baseCRL if the current CRL is a delta CRL")
    private Boolean withBaseCrl = Boolean.FALSE;

    @Option(name = "--basecrl-out",
        description = "where to save the baseCRL\n(defaults to <out>-baseCRL)")
    @Completion(FileCompleter.class)
    private String baseCrlOut;

    @Override
    protected X509CRL retrieveCrl() throws CmpClientException, PkiErrorException {
      ReqRespDebug debug = getReqRespDebug();
      try {
        return client.downloadCrl(caName, debug);
      } finally {
        saveRequestResponse(debug);
      }
    }

    @Override
    protected Object execute0() throws Exception {
      if (caName != null) {
        caName = caName.toLowerCase();
      }

      Set<String> caNames = client.getCaNames();
      if (isEmpty(caNames)) {
        throw new IllegalCmdParamException("no CA is configured");
      }

      if (caName != null && !caNames.contains(caName)) {
        throw new IllegalCmdParamException("CA " + caName + " is not within the configured CAs "
            + caNames);
      }

      if (caName == null) {
        if (caNames.size() == 1) {
          caName = caNames.iterator().next();
        } else {
          throw new IllegalCmdParamException("no CA is specified, one of " + caNames
              + " is required");
        }
      }

      X509CRL crl = null;
      try {
        crl = retrieveCrl();
      } catch (PkiErrorException ex) {
        throw new CmdFailure("received no CRL from server: " + ex.getMessage());
      }

      if (crl == null) {
        throw new CmdFailure("received no CRL from server");
      }

      saveVerbose("saved CRL to file", outFile, encodeCrl(crl.getEncoded(), outform));

      if (!withBaseCrl.booleanValue()) {
        return null;
      }

      byte[] octetString = crl.getExtensionValue(Extension.deltaCRLIndicator.getId());
      if (octetString == null) {
        return null;
      }

      if (baseCrlOut == null) {
        baseCrlOut = outFile + "-baseCRL";
      }

      byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
      BigInteger baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();

      ReqRespDebug debug = getReqRespDebug();
      try {
        crl = client.downloadCrl(caName, baseCrlNumber, debug);
      } catch (PkiErrorException ex) {
        throw new CmdFailure("received no baseCRL from server: " + ex.getMessage());
      } finally {
        saveRequestResponse(debug);
      }

      if (crl == null) {
        throw new CmdFailure("received no baseCRL from server");
      }

      saveVerbose("saved baseCRL to file", baseCrlOut, encodeCrl(crl.getEncoded(), outform));
      return null;
    } // method execute0

  }

  @Command(scope = "xi", name = "cmp-health", description = "check healty status of CA")
  @Service
  public static class CmpHealth extends ClientAction {

    @Option(name = "--ca", description = "CA name\n(required if multiple CAs are configured)")
    @Completion(CmpClientCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--verbose", aliases = "-v", description = "show status verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      if (caName != null) {
        caName = caName.toLowerCase();
      }

      Set<String> caNames = client.getCaNames();
      if (isEmpty(caNames)) {
        throw new IllegalCmdParamException("no CA is configured");
      }

      if (caName != null && !caNames.contains(caName)) {
        throw new IllegalCmdParamException("CA " + caName + " is not within the configured CAs "
            + caNames);
      }

      if (caName == null) {
        if (caNames.size() == 1) {
          caName = caNames.iterator().next();
        } else {
          throw new IllegalCmdParamException("no CA is specified, one of " + caNames
              + " is required");
        }
      }

      HealthCheckResult healthResult = client.getHealthCheckResult(caName);
      String str = StringUtil.concat("healthy status for CA ", caName, ": ",
          (healthResult.isHealthy() ? "healthy" : "not healthy"));
      if (verbose) {
        str = StringUtil.concat(str, "\n", JSON.toJSONString(healthResult, true));
      }
      System.out.println(str);
      return null;
    } // method execute0

  }

  @Command(scope = "xi", name = "cmp-enroll-p11",
      description = "enroll certificate (PKCS#11 token)")
  @Service
  public static class CmpEnrollP11 extends EnrollCertAction {

    @Option(name = "--slot", required = true, description = "slot index")
    private Integer slotIndex;

    @Option(name = "--key-id",
        description = "id of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    private String keyId;

    @Option(name = "--key-label",
        description = "label of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    private String keyLabel;

    @Option(name = "--module", description = "name of the PKCS#11 module")
    private String moduleName = "default";

    private ConcurrentContentSigner signer;

    @Override
    protected ConcurrentContentSigner getSigner() throws ObjectCreationException {
      if (signer == null) {
        byte[] keyIdBytes = null;
        if (keyId != null) {
          keyIdBytes = Hex.decode(keyId);
        }

        SignerConf signerConf = getPkcs11SignerConf(moduleName, slotIndex, keyLabel,
            keyIdBytes, HashAlgo.getInstance(hashAlgo), getSignatureAlgoControl());
        signer = securityFactory.createSigner("PKCS11", signerConf, (X509Certificate[]) null);
      }
      return signer;
    }

    public static SignerConf getPkcs11SignerConf(String pkcs11ModuleName, Integer slotIndex,
        String keyLabel, byte[] keyId, HashAlgo hashAlgo,
        SignatureAlgoControl signatureAlgoControl) {
      Args.notNull(hashAlgo, "hashAlgo");
      Args.notNull(slotIndex, "slotIndex");

      if (keyId == null && keyLabel == null) {
        throw new IllegalArgumentException("at least one of keyId and keyLabel may not be null");
      }

      ConfPairs conf = new ConfPairs();
      conf.putPair("parallelism", Integer.toString(1));

      if (pkcs11ModuleName != null && pkcs11ModuleName.length() > 0) {
        conf.putPair("module", pkcs11ModuleName);
      }

      if (slotIndex != null) {
        conf.putPair("slot", slotIndex.toString());
      }

      if (keyId != null) {
        conf.putPair("key-id", Hex.encode(keyId));
      }

      if (keyLabel != null) {
        conf.putPair("key-label", keyLabel);
      }

      return new SignerConf(conf.getEncoded(), hashAlgo, signatureAlgoControl);
    }

  }

  @Command(scope = "xi", name = "cmp-update-p11",
      description = "update certificate (PKCS#11 token)")
  @Service
  public static class CmpUpdateP11 extends UpdateCertAction {

    @Option(name = "--slot", required = true, description = "slot index")
    private Integer slotIndex;

    @Option(name = "--key-id",
        description = "id of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    private String keyId;

    @Option(name = "--key-label",
        description = "label of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    private String keyLabel;

    @Option(name = "--module", description = "name of the PKCS#11 module")
    private String moduleName = "default";

    private ConcurrentContentSigner signer;

    @Override
    protected ConcurrentContentSigner getSigner() throws ObjectCreationException {
      if (signer == null) {
        byte[] keyIdBytes = null;
        if (keyId != null) {
          keyIdBytes = Hex.decode(keyId);
        }

        SignerConf signerConf = getPkcs11SignerConf(moduleName, slotIndex, keyLabel,
            keyIdBytes, HashAlgo.getInstance(hashAlgo), getSignatureAlgoControl());
        signer = securityFactory.createSigner("PKCS11", signerConf, (X509Certificate[]) null);
      }
      return signer;
    }

    public static SignerConf getPkcs11SignerConf(String pkcs11ModuleName, Integer slotIndex,
        String keyLabel, byte[] keyId, HashAlgo hashAlgo,
        SignatureAlgoControl signatureAlgoControl) {
      Args.notNull(hashAlgo, "hashAlgo");
      Args.notNull(slotIndex, "slotIndex");

      if (keyId == null && keyLabel == null) {
        throw new IllegalArgumentException("at least one of keyId and keyLabel may not be null");
      }

      ConfPairs conf = new ConfPairs();
      conf.putPair("parallelism", Integer.toString(1));

      if (pkcs11ModuleName != null && pkcs11ModuleName.length() > 0) {
        conf.putPair("module", pkcs11ModuleName);
      }

      if (slotIndex != null) {
        conf.putPair("slot", slotIndex.toString());
      }

      if (keyId != null) {
        conf.putPair("key-id", Hex.encode(keyId));
      }

      if (keyLabel != null) {
        conf.putPair("key-label", keyLabel);
      }

      return new SignerConf(conf.getEncoded(), hashAlgo, signatureAlgoControl);
    }

  }

  @Command(scope = "xi", name = "cmp-enroll-p12",
      description = "enroll certificate (PKCS#12 keystore)")
  @Service
  public static class CmpEnrollP12 extends EnrollCertAction {

    @Option(name = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FileCompleter.class)
    private String p12File;

    @Option(name = "--password", description = "password of the PKCS#12 keystore file")
    private String password;

    private ConcurrentContentSigner signer;

    @Override
    protected ConcurrentContentSigner getSigner() throws ObjectCreationException {
      if (signer == null) {
        if (password == null) {
          try {
            password = new String(readPassword());
          } catch (IOException ex) {
            throw new ObjectCreationException("could not read password: " + ex.getMessage(), ex);
          }
        }

        ConfPairs conf = new ConfPairs("password", password);
        conf.putPair("parallelism", Integer.toString(1));
        conf.putPair("keystore", "file:" + p12File);
        SignerConf signerConf = new SignerConf(conf.getEncoded(),
            HashAlgo.getNonNullInstance(hashAlgo), getSignatureAlgoControl());
        signer = securityFactory.createSigner("PKCS12", signerConf, (X509Certificate[]) null);
      }
      return signer;
    }

  }

  @Command(scope = "xi", name = "cmp-update-p12",
      description = "update certificate (PKCS#12 keystore)")
  @Service
  public static class CmpUpdateP12 extends UpdateCertAction {

    @Option(name = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FileCompleter.class)
    private String p12File;

    @Option(name = "--password", description = "password of the PKCS#12 keystore file")
    private String password;

    private ConcurrentContentSigner signer;

    @Override
    protected ConcurrentContentSigner getSigner() throws ObjectCreationException {
      if (signer == null) {
        if (password == null) {
          try {
            password = new String(readPassword());
          } catch (IOException ex) {
            throw new ObjectCreationException("could not read password: " + ex.getMessage(), ex);
          }
        }

        ConfPairs conf = new ConfPairs("password", password);
        conf.putPair("parallelism", Integer.toString(1));
        conf.putPair("keystore", "file:" + p12File);
        SignerConf signerConf = new SignerConf(conf.getEncoded(),
            HashAlgo.getNonNullInstance(hashAlgo), getSignatureAlgoControl());
        signer = securityFactory.createSigner("PKCS12", signerConf, (X509Certificate[]) null);
      }
      return signer;
    }

  }

  @Command(scope = "xi", name = "cmp-rm-cert", description = "remove certificate")
  @Service
  public static class CmpRmCert extends UnRevRemoveCertAction {

    @Override
    protected Object execute0() throws Exception {
      if (!(certFile == null ^ getSerialNumber() == null)) {
        throw new IllegalCmdParamException("exactly one of cert and serial must be specified");
      }

      ReqRespDebug debug = getReqRespDebug();
      CertIdOrError certIdOrError;
      try {
        if (certFile != null) {
          X509Certificate cert = X509Util.parseCert(new File(certFile));
          certIdOrError = client.removeCert(caName, cert, debug);
        } else {
          certIdOrError = client.removeCert(caName, getSerialNumber(), debug);
        }
      } finally {
        saveRequestResponse(debug);
      }

      if (certIdOrError.getError() != null) {
        PkiStatusInfo error = certIdOrError.getError();
        throw new CmdFailure("removing certificate failed: " + error);
      } else {
        println("removed certificate");
      }
      return null;
    } // method execute0

  }

  @Command(scope = "xi", name = "cmp-revoke", description = "revoke certificate")
  @Service
  public static class CmpRevoke extends UnRevRemoveCertAction {

    @Option(name = "--reason", aliases = "-r", required = true, description = "CRL reason")
    @Completion(Completers.ClientCrlReasonCompleter.class)
    private String reason;

    @Option(name = "--inv-date", description = "invalidity date, UTC time of format yyyyMMddHHmmss")
    private String invalidityDateS;

    @Override
    protected Object execute0() throws Exception {
      if (!(certFile == null ^ getSerialNumber() == null)) {
        throw new IllegalCmdParamException("exactly one of cert and serial must be specified");
      }

      CrlReason crlReason = CrlReason.forNameOrText(reason);

      if (!CrlReason.PERMITTED_CLIENT_CRLREASONS.contains(crlReason)) {
        throw new IllegalCmdParamException("reason " + reason + " is not permitted");
      }

      CertIdOrError certIdOrError;

      Date invalidityDate = null;
      if (isNotBlank(invalidityDateS)) {
        invalidityDate = DateUtil.parseUtcTimeyyyyMMddhhmmss(invalidityDateS);
      }

      ReqRespDebug debug = getReqRespDebug();
      try {
        if (certFile != null) {
          X509Certificate cert = X509Util.parseCert(new File(certFile));
          certIdOrError = client.revokeCert(caName, cert, crlReason.getCode(), invalidityDate,
              debug);
        } else {
          certIdOrError = client.revokeCert(caName, getSerialNumber(), crlReason.getCode(),
              invalidityDate, debug);
        }
      } finally {
        saveRequestResponse(debug);
      }

      if (certIdOrError.getError() != null) {
        PkiStatusInfo error = certIdOrError.getError();
        throw new CmdFailure("revocation failed: " + error);
      } else {
        println("revoked certificate");
      }
      return null;
    } // method execute0

  }

  @Command(scope = "xi", name = "cmp-unrevoke", description = "unrevoke certificate")
  @Service
  public static class CmpUnrevoke extends UnRevRemoveCertAction {

    @Override
    protected Object execute0() throws Exception {
      if (!(certFile == null ^ getSerialNumber() == null)) {
        throw new IllegalCmdParamException("exactly one of cert and serial must be specified");
      }

      ReqRespDebug debug = getReqRespDebug();
      CertIdOrError certIdOrError;
      try {
        if (certFile != null) {
          X509Certificate cert = X509Util.parseCert(new File(certFile));
          certIdOrError = client.unrevokeCert(caName, cert, debug);
        } else {
          certIdOrError = client.unrevokeCert(caName, getSerialNumber(), debug);
        }
      } finally {
        saveRequestResponse(debug);
      }

      if (certIdOrError.getError() != null) {
        PkiStatusInfo error = certIdOrError.getError();
        throw new CmdFailure("releasing revocation failed: " + error);
      } else {
        println("unrevoked certificate");
      }
      return null;
    } // method execute0

  }

  public abstract static class UnRevRemoveCertAction extends ClientAction {

    @Option(name = "--ca", description = "CA name\n(required if more than one CA is configured)")
    @Completion(CmpClientCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(name = "--cert", aliases = "-c",
        description = "certificate file (either cert or serial must be specified)")
    @Completion(FileCompleter.class)
    protected String certFile;

    @Option(name = "--serial", aliases = "-s",
        description = "serial number (either cert or serial must be specified)")
    private String serialNumberS;

    private BigInteger serialNumber;

    protected BigInteger getSerialNumber() {
      if (serialNumber == null) {
        if (isNotBlank(serialNumberS)) {
          this.serialNumber = toBigInt(serialNumberS);
        }
      }
      return serialNumber;
    }

    protected String checkCertificate(X509Certificate cert, X509Certificate caCert)
        throws CertificateEncodingException {
      if (caName != null) {
        caName = caName.toLowerCase();
      }

      Args.notNull(cert, "cert");
      Args.notNull(caCert, "caCert");

      if (!cert.getIssuerX500Principal().equals(caCert.getSubjectX500Principal())) {
        return "the given certificate is not issued by the given issuer";
      }

      byte[] caSki = X509Util.extractSki(caCert);
      byte[] aki = X509Util.extractAki(cert);
      if (caSki != null && aki != null) {
        if (!Arrays.equals(aki, caSki)) {
          return "the given certificate is not issued by the given issuer";
        }
      }

      try {
        cert.verify(caCert.getPublicKey(), "BC");
      } catch (SignatureException ex) {
        return "could not verify the signature of given certificate by the issuer";
      } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException
          | NoSuchProviderException ex) {
        return "could not verify the signature of given certificate by the issuer: "
                  + ex.getMessage();
      }

      return null;
    }

  }

  public abstract static class UpdateAction extends ClientAction {

    @Reference
    protected SecurityFactory securityFactory;

    @Option(name = "--subject", aliases = "-s",
        description = "subject to be requested")
    private String subject;

    @Option(name = "--not-before", description = "notBefore, UTC time of format yyyyMMddHHmmss")
    private String notBeforeS;

    @Option(name = "--not-after", description = "notAfter, UTC time of format yyyyMMddHHmmss")
    private String notAfterS;

    @Option(name = "--ca", description = "CA name\n(required if more than one CA is configured)")
    @Completion(CmpClientCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--oldcert", description = "certificate files (exactly one of oldcert and\n"
        + " oldcert-serial must be specified")
    @Completion(FileCompleter.class)
    private String oldCertFile;

    @Option(name = "--oldcert-serial", description = "serial number of the old certificate")
    private String oldCSerialNumber;

    @Option(name = "--need-extension", multiValued = true,
        description = "type (name or OID) of extension that must be contained in the certificate")
    @Completion(Completers.ExtensionNameCompleter.class)
    private List<String> needExtensionTypes;

    @Option(name = "--want-extension", multiValued = true,
        description = "type (name or OID) of extension that should be contained in the"
            + " certificate if possible")
    @Completion(Completers.ExtensionNameCompleter.class)
    private List<String> wantExtensionTypes;

    protected abstract SubjectPublicKeyInfo getPublicKey() throws Exception;

    protected abstract EnrollCertRequest.Entry buildEnrollCertRequestEntry(
        String id, String profile, CertRequest certRequest) throws Exception;

    protected EnrollCertResult enroll() throws Exception {
      Set<String> caNames = client.getCaNames();
      if (caName != null) {
        caName = caName.toLowerCase();
        if (!caNames.contains(caName)) {
          throw new IllegalCmdParamException("unknown CA " + caName);
        }
      } else {
        if (caNames.size() != 1) {
          throw new IllegalCmdParamException("please specify the CA");
        } else {
          caName = caNames.iterator().next();
        }
      }

      if (needExtensionTypes != null) {
        needExtensionTypes = EnrollAction.resolveExtensionTypes(needExtensionTypes);
      } else {
        needExtensionTypes = new LinkedList<>();
      }

      if (wantExtensionTypes != null) {
        wantExtensionTypes = EnrollAction.resolveExtensionTypes(wantExtensionTypes);
      } else {
        wantExtensionTypes = new LinkedList<>();
      }

      CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();

      if (subject != null && !subject.isEmpty()) {
        certTemplateBuilder.setSubject(new X500Name(subject));
      }

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

      List<Extension> extensions = new LinkedList<>();

      if (isNotEmpty(needExtensionTypes) || isNotEmpty(wantExtensionTypes)) {
        ExtensionExistence ee = new ExtensionExistence(
            EnrollAction.textToAsn1ObjectIdentifers(needExtensionTypes),
            EnrollAction.textToAsn1ObjectIdentifers(wantExtensionTypes));
        extensions.add(new Extension(ObjectIdentifiers.id_xipki_ext_cmpRequestExtensions, false,
                          ee.toASN1Primitive().getEncoded()));
      }

      if (isNotEmpty(extensions)) {
        Extensions asn1Extensions = new Extensions(extensions.toArray(new Extension[0]));
        certTemplateBuilder.setExtensions(asn1Extensions);
      }

      if (!(oldCertFile == null ^ oldCSerialNumber == null)) {
        throw new IllegalCmdParamException(
            "exactly one of oldcert and oldcert-serial must be specified");
      }

      CertId oldCertId;
      if (oldCertFile != null) {
        org.bouncycastle.asn1.x509.Certificate oldCert =
            X509Util.parseBcCert(new File(oldCertFile));
        oldCertId = new CertId(new GeneralName(oldCert.getIssuer()), oldCert.getSerialNumber());
      } else {
        X500Name issuer = client.getCaCertSubject(caName);
        oldCertId = new CertId(new GeneralName(issuer), toBigInt(oldCSerialNumber));
      }

      Controls controls = new Controls(
          new AttributeTypeAndValue(CMPObjectIdentifiers.regCtrl_oldCertID, oldCertId));

      CertRequest certReq = new CertRequest(1, certTemplateBuilder.build(), controls);

      EnrollCertRequest.Entry reqEntry = buildEnrollCertRequestEntry("id-1", null, certReq);
      EnrollCertRequest request = new EnrollCertRequest(EnrollCertRequest.EnrollType.KEY_UPDATE);
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

  }

  public abstract static class UpdateCertAction extends UpdateAction {

    @Option(name = "--hash", description = "hash algorithm name for the POPO computation")
    protected String hashAlgo = "SHA256";

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Option(name = "--rsa-mgf1",
        description = "whether to use the RSAPSS MGF1 for the POPO computation\n"
            + "(only applied to RSA key)")
    private Boolean rsaMgf1 = Boolean.FALSE;

    @Option(name = "--dsa-plain",
        description = "whether to use the Plain DSA for the POPO computation\n"
            + "(only applied to DSA and ECDSA key)")
    private Boolean dsaPlain = Boolean.FALSE;

    @Option(name = "--gm",
        description = "whether to use the chinese GM algorithm for the POPO computation\n"
            + "(only applied to EC key with GM curves)")
    private Boolean gm = Boolean.FALSE;

    @Option(name = "--embeds-publickey",
        description = "whether to embed the public key in the request")
    private Boolean embedsPulibcKey = Boolean.FALSE;

    protected SignatureAlgoControl getSignatureAlgoControl() {
      return new SignatureAlgoControl(rsaMgf1, dsaPlain, gm);
    }

    /**
     * TODO.
     * @param signatureAlgoControl
     *          Signature algorithm control. Must not be {@code null}.
     */
    protected abstract ConcurrentContentSigner getSigner() throws ObjectCreationException;

    protected SubjectPublicKeyInfo getPublicKey() throws Exception {
      if (!embedsPulibcKey) {
        return null;
      } else {
        ConcurrentContentSigner signer = getSigner();
        X509CertificateHolder ssCert = signer.getBcCertificate();
        return ssCert.getSubjectPublicKeyInfo();
      }
    }

    @Override
    protected EnrollCertRequest.Entry buildEnrollCertRequestEntry(String id, String profile,
        CertRequest certRequest) throws Exception {
      ConcurrentContentSigner signer = getSigner();

      ProofOfPossessionSigningKeyBuilder popoBuilder =
          new ProofOfPossessionSigningKeyBuilder(certRequest);
      ConcurrentBagEntrySigner signer0 = signer.borrowSigner();
      POPOSigningKey popoSk;
      try {
        popoSk = popoBuilder.build(signer0.value());
      } finally {
        signer.requiteSigner(signer0);
      }

      ProofOfPossession popo = new ProofOfPossession(popoSk);
      final boolean caGenKeypair = false;
      final boolean kup = true;

      return new EnrollCertRequest.Entry(id, profile, certRequest, popo, caGenKeypair, kup);
    }

    @Override
    protected Object execute0() throws Exception {
      EnrollCertResult result = enroll();

      X509Certificate cert = null;
      if (result != null) {
        String id = result.getAllIds().iterator().next();
        CertifiedKeyPairOrError certOrError = result.getCertOrError(id);
        cert = (X509Certificate) certOrError.getCertificate();
      }

      if (cert == null) {
        throw new CmdFailure("no certificate received from the server");
      }

      saveVerbose("saved certificate to file", outputFile, encodeCert(cert.getEncoded(), outform));

      return null;
    } // method execute0

  }

  @Command(scope = "xi", name = "cmp-update-cagenkey",
      description = "update certificate (keypair will be generated by the CA)")
  @Service
  public static class CmpUpdateCagenkey extends UpdateAction {

    @Option(name = "--cert-outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String certOutform = "der";

    @Option(name = "--cert-out", description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String certOutputFile;

    @Option(name = "--p12-out", required = true, description = "where to save the PKCS#12 keystore")
    @Completion(FileCompleter.class)
    private String p12OutputFile;

    @Option(name = "--password", description = "password of the PKCS#12 file")
    private String password;

    @Override
    protected SubjectPublicKeyInfo getPublicKey() throws Exception {
      return null;
    }

    @Override
    protected EnrollCertRequest.Entry buildEnrollCertRequestEntry(String id, String profile,
        CertRequest certRequest) throws Exception {
      final boolean caGenKeypair = true;
      final boolean kup = true;
      return new EnrollCertRequest.Entry("id-1", profile, certRequest, null, caGenKeypair, kup);
    }

    @Override
    protected Object execute0() throws Exception {
      EnrollCertResult result = enroll();

      X509Certificate cert = null;
      PrivateKeyInfo privateKeyInfo = null;
      if (result != null) {
        String id = result.getAllIds().iterator().next();
        CertifiedKeyPairOrError certOrError = result.getCertOrError(id);
        cert = (X509Certificate) certOrError.getCertificate();
        privateKeyInfo = certOrError.getPrivateKeyInfo();
      }

      if (cert == null) {
        throw new CmdFailure("no certificate received from the server");
      }

      if (privateKeyInfo == null) {
        throw new CmdFailure("no private key received from the server");
      }

      if (StringUtil.isNotBlank(certOutputFile)) {
        saveVerbose("saved certificate to file", certOutputFile,
            encodeCert(cert.getEncoded(), certOutform));
      }

      PrivateKey privateKey = BouncyCastleProvider.getPrivateKey(privateKeyInfo);

      KeyStore ks = KeyStore.getInstance("PKCS12");
      char[] pwd = getPassword();
      ks.load(null, pwd);
      ks.setKeyEntry("main", privateKey, pwd, new Certificate[] {cert});
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      ks.store(bout, pwd);
      saveVerbose("saved key to file", p12OutputFile, bout.toByteArray());

      return null;
    } // method execute0

    private char[] getPassword() throws IOException {
      char[] pwdInChar = readPasswordIfNotSet(password);
      if (pwdInChar != null) {
        password = new String(pwdInChar);
      }
      return pwdInChar;
    }
  }

}
