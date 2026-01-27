// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.apache.karaf.shell.support.completers.StringsCompleter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
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
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.xipki.cmp.client.CmpClientException;
import org.xipki.cmp.client.EnrollCertRequest;
import org.xipki.cmp.client.EnrollCertRequest.EnrollType;
import org.xipki.cmp.client.EnrollCertResult;
import org.xipki.cmp.client.EnrollCertResult.CertifiedKeyPairOrError;
import org.xipki.cmp.client.PkiErrorException;
import org.xipki.security.*;
import org.xipki.security.encap.KemEncapKey;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.codec.Hex;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.extra.misc.ReqRespDebug;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import org.xipki.util.password.PasswordResolverException;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * CMP client actions to enroll certificates.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class EnrollCertActions {

  @Command(scope = "xi", name = "cmp-csr-enroll", description =
      "enroll certificate via CSR")
  @Service
  public static class CmpCsrEnroll extends CmpActions.AuthClientAction {

    @Option(name = "--csr", required = true, description = "CSR file")
    @Completion(FileCompleter.class)
    private String csrFile;

    @Option(name = "--profile", aliases = "-p", required = true,
        description = "certificate profile")
    private String profile;

    @Option(name = "--not-before", description =
        "notBefore, UTC time of format yyyyMMddHHmmss")
    private String notBeforeS;

    @Option(name = "--not-after", description =
        "notAfter, UTC time of format yyyyMMddHHmmss")
    private String notAfterS;

    @Option(name = "--outform", description =
        "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description =
        "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Override
    protected Object execute0() throws Exception {
      CertificationRequest csr = X509Util.parseCsr(new File(csrFile));

      Instant notBefore = StringUtil.isNotBlank(notBeforeS)
          ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notBeforeS) : null;

      Instant notAfter = StringUtil.isNotBlank(notAfterS)
          ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notAfterS) : null;

      EnrollCertResult result;
      ReqRespDebug debug = getReqRespDebug();
      try {
        result = client.enrollCert(caName, getRequestor(), csr, profile,
                  notBefore, notAfter, debug);
      } finally {
        saveRequestResponse(debug);
      }

      CertifiedKeyPairOrError certOrError = null;
      if (result != null) {
        String id = result.getAllIds().iterator().next();
        certOrError = result.getCertOrError(id);
      }

      if (certOrError == null) {
        throw new CmdFailure("error, received neither certificate nor error");
      } else if (certOrError.getError() != null) {
        throw new CmdFailure(certOrError.getError().toString());
      }

      saveVerbose("certificate saved to file", outputFile,
          encodeCert(certOrError.getCertificate().getEncoded(), outform));
      return null;
    } // method execute0

  } // class CmpCsrEnroll

  @Command(scope = "xi", name = "cmp-enroll-serverkeygen",
      description = "enroll certificate (keypair will be generated by the CA)")
  @Service
  public static class CmpEnrollCagenkey extends EnrollAction {

    @Option(name = "--cmpreq-type", description =
        "CMP request type (ir for Initialization Request,\n" +
        "and cr for Certification Request)")
    @Completion(value = StringsCompleter.class, values = {"ir", "cr"})
    private String cmpreqType = "cr";

    @Option(name = "--cert-outform", description =
        "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String certOutform = "der";

    @Option(name = "--cert-out", description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String certOutputFile;

    @Option(name = "--p12-out", required = true, description =
        "where to save the PKCS#12 keystore")
    @Completion(FileCompleter.class)
    private String p12OutputFile;

    @Option(name = "--password", description =
        "password of the PKCS#12 file, as plaintext or PBE-encrypted.")
    private String passwordHint;

    @Override
    protected SubjectPublicKeyInfo getPublicKey() throws Exception {
      return null;
    }

    @Override
    protected EnrollCertRequest.Entry buildEnrollCertRequestEntry(
        String id, String profile, CertRequest certRequest)
        throws Exception {
      return new EnrollCertRequest.Entry("id-1", profile, certRequest,
          null, true, false);
    }

    @Override
    protected Object execute0() throws Exception {
      EnrollCertResult result = enroll();

      CertifiedKeyPairOrError certOrError = null;
      if (result != null) {
        String id = result.getAllIds().iterator().next();
        certOrError = result.getCertOrError(id);
      }

      if (certOrError == null) {
        throw new CmdFailure("error, received neither certificate nor error");
      } else if (certOrError.getError() != null) {
        throw new CmdFailure(certOrError.getError().toString());
      }

      X509Cert cert = Optional.ofNullable(certOrError.getCertificate())
          .orElseThrow(() -> new CmdFailure(
              "no certificate received from the server"));
      PrivateKeyInfo privateKeyInfo = Optional.ofNullable(
          certOrError.getPrivateKeyInfo()).orElseThrow(
              () -> new CmdFailure("no private key received from the server"));

      if (StringUtil.isNotBlank(certOutputFile)) {
        saveVerbose("saved certificate to file", certOutputFile,
            encodeCert(cert.getEncoded(), certOutform));
      }

      X509Cert[] caCertChain = result.getCaCertChain();
      int size = caCertChain == null ? 1 : 1 + caCertChain.length;
      X509Certificate[] certchain = new X509Certificate[size];
      certchain[0] = cert.toJceCert();
      if (size > 1) {
        for (int i = 0; i < caCertChain.length; i++) {
          certchain[i + 1] = caCertChain[i].toJceCert();
        }
      }

      PrivateKey privateKey = KeyUtil.getPrivateKey(privateKeyInfo);

      KeyStore ks = KeyUtil.getOutKeyStore("PKCS12");
      char[] pwd = getPassword();
      ks.load(null, pwd);
      ks.setKeyEntry("main", privateKey, pwd, certchain);
      try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
        ks.store(bout, pwd);
        saveVerbose("saved key to file", p12OutputFile,
            bout.toByteArray());
      }

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
    } // method getCmpReqType

    private char[] getPassword() throws IOException, PasswordResolverException {
      char[] pwdInChar = readPasswordIfNotSet(passwordHint);
      if (pwdInChar != null) {
        passwordHint = new String(pwdInChar);
      }
      return pwdInChar;
    } // method getPassword

  } // class CmpEnrollCagenkey

  @Command(scope = "xi", name = "cmp-enroll-p11", description =
      "enroll certificate (PKCS#11 token)")
  @Service
  public static class CmpEnrollP11 extends EnrollCertAction {

    @Option(name = "--slot", required = true, description = "slot index")
    private String slotIndex = "0";

    @Option(name = "--key-id", description =
        "id of the private key in the PKCS#11 device\n" +
        "either keyId or keyLabel must be specified")
    private String keyId;

    @Option(name = "--key-label", description =
        "label of the private key in the PKCS#11 device\n" +
        "either keyId or keyLabel must be specified")
    private String keyLabel;

    @Option(name = "--module", description = "name of the PKCS#11 module")
    private String moduleName = "default";

    private ConcurrentContentSigner signer;

    @Override
    protected ConcurrentContentSigner getSigner()
        throws ObjectCreationException {
      if (signer == null) {
        byte[] keyIdBytes = null;
        if (keyId != null) {
          keyIdBytes = Hex.decode(keyId);
        }

        SignerConf signerConf = getPkcs11SignerConf(moduleName,
            Integer.parseInt(slotIndex), keyLabel, keyIdBytes, null,
            getSignAlgoMode());
        signer = securityFactory.createSigner(
                "PKCS11", signerConf, (X509Cert[]) null);
      }
      return signer;
    } // method getSigner

    public static SignerConf getPkcs11SignerConf(
        String pkcs11ModuleName, int slotIndex, String keyLabel, byte[] keyId,
        HashAlgo hashAlgo, SignAlgoMode mode) {
      if (keyId == null && keyLabel == null) {
        throw new IllegalArgumentException(
            "at least one of keyId and keyLabel may not be null");
      }

      ConfPairs conf = new ConfPairs();
      conf.putPair("parallelism", Integer.toString(1));

      if (pkcs11ModuleName != null && !pkcs11ModuleName.isEmpty()) {
        conf.putPair("module", pkcs11ModuleName);
      }

      conf.putPair("slot", Integer.toString(slotIndex));

      if (keyId != null) {
        conf.putPair("key-id", Hex.encode(keyId));
      }

      if (keyLabel != null) {
        conf.putPair("key-label", keyLabel);
      }

      if (hashAlgo != null) {
        conf.putPair("hash", hashAlgo.getJceName());
      }

      if (mode != null) {
        conf.putPair("mode", mode.name());
      }

      return new SignerConf(conf.getEncoded());
    } // method getPkcs11SignerConf

  } // class CmpEnrollP11

  @Command(scope = "xi", name = "cmp-enroll-p12",
      description = "enroll certificate (PKCS#12 keystore)")
  @Service
  public static class CmpEnrollP12 extends EnrollCertAction {

    @Option(name = "--p12", required = true, description =
        "PKCS#12 keystore file")
    @Completion(FileCompleter.class)
    private String p12File;

    @Option(name = "--password", description =
        "password of the PKCS#12 keystore file, as plaintext or " +
        "PBE-encrypted.")
    private String passwordHint;

    private ConcurrentContentSigner signer;

    @Override
    protected ConcurrentContentSigner getSigner()
      throws ObjectCreationException, CmpClientException {
      if (signer == null) {
        char[] password;
        try {
          password = readPasswordIfNotSet("Enter keystore password",
              passwordHint);
        } catch (IOException | PasswordResolverException ex) {
          throw new ObjectCreationException(
              "could not read password: " + ex.getMessage(), ex);
        }

        SignerConf sc = new SignerConf();
        sc.setPassword(new String(password))
            .setParallelism(1)
            .setKeystore("file:" + p12File);

        SubjectPublicKeyInfo tmpPkInfo = null;
        try {
          tmpPkInfo = KeyUtil.getPublicKeyOfFirstKeyEntry(
              "PKCS12", p12File, password);
        } catch (Exception e) {
        }

        SubjectPublicKeyInfo pkInfo = tmpPkInfo;

        SignAlgoMode mode = getSignAlgoMode();
        if (mode != null) {
          sc.setMode(mode);
        }

        KeySpec keySpec = pkInfo == null ? null : KeySpec.ofPublicKey(pkInfo);

        if (keySpec != null) {
          if (keySpec.isMlkem() || keySpec.isCompositeMLKEM()) {
            CreateSignerCallback callback = new CreateSignerCallback() {
              @Override
              public KemEncapKey generateKemEncapKey(
                  SecurityFactory securityFactory,
                  SubjectPublicKeyInfo publicKeyInfo)
                  throws XiSecurityException {
                try {
                  return client.generateKemEncapKey(caName, pkInfo, null);
                } catch (CmpClientException | PkiErrorException e) {
                  throw new XiSecurityException(
                      "error generating KemEncapKey: " + e.getMessage());
                }
              }

              @Override
              public SignAlgo getSignAlgo(KeySpec keyspec, SignAlgoMode mode) {
                return SignAlgo.KEM_HMAC_SHA256;
              }
            };

            sc.setCallback(callback);
          } else if (keySpec.isMontgomeryEC()) {
            List<X509Cert> peerCerts = client.getDhPopPeerCertificates();
            if (CollectionUtil.isNotEmpty(peerCerts)) {
              sc.setPeerCertificates(peerCerts);
            }
          }
        }

        signer = securityFactory.createSigner("PKCS12", sc,
            (X509Cert[]) null);
      }
      return signer;
    } // method getSigner

  } // class CmpEnrollP12

  public abstract static class EnrollAction
      extends CmpActions.AuthClientAction {

    @Reference
    protected SecurityFactory securityFactory;

    @Option(name = "--subject", aliases = "-s", required = true,
        description = "subject to be requested")
    private String subject;

    @Option(name = "--profile", aliases = "-p", required = true,
        description = "certificate profile")
    private String profile;

    @Option(name = "--not-before", description =
        "notBefore, UTC time of format yyyyMMddHHmmss")
    private String notBeforeS;

    @Option(name = "--not-after", description =
        "notAfter, UTC time of format yyyyMMddHHmmss")
    private String notAfterS;

    @Option(name = "--keyusage", multiValued = true, description = "keyusage")
    @Completion(Completers.KeyusageCompleter.class)
    private List<String> keyusages;

    @Option(name = "--ext-keyusage", multiValued = true, description =
        "extended keyusage (name or OID")
    @Completion(Completers.ExtKeyusageCompleter.class)
    private List<String> extkeyusages;

    @Option(name = "--subject-alt-name", aliases = "--san", multiValued = true,
        description =
            "subjectAltName, in the form of [tagNo]value or [tagText]value. "
            + "Valid tagNo/tagText/value:\n"
            + " '0'/'othername'/OID=[DirectoryStringChoice:]value,\n"
            + "    valid DirectoryStringChoices are printableString and "
            +      "utf8String,\n"
            + "    default to utf8Sring"
            + " '1'/'email'/text,\n"
            + " '2'/'dns'/text,\n"
            + " '4'/'dirName'/X500 name e.g. CN=abc,\n"
            + " '5'/'edi'/key=value,\n"
            + " '6'/'uri'/text,\n"
            + " '7'/'ip'/IP address,\n"
            + " '8'/'rid'/OID")
    private List<String> subjectAltNames;

    @Option(name = "--subject-info-access", multiValued = true, description =
        "subjectInfoAccess")
    private List<String> subjectInfoAccesses;

    @Option(name = "--qc-eu-limit", multiValued = true, description =
        "QC EuLimitValue of format <currency>:<amount>:<exponent>.")
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

    @Option(name = "--dateOfBirth", description =
        "Date of birth YYYYMMdd in subject")
    private String dateOfBirth;

    @Option(name = "--postalAddress", multiValued = true, description =
        "postal address in subject")
    private List<String> postalAddress;

    @Option(name = "--extensions-file", description =
        "File containing the DER-encoded Extensions")
    @Completion(FileCompleter.class)
    private String extensionsFile;

    protected abstract SubjectPublicKeyInfo getPublicKey() throws Exception;

    protected abstract EnrollCertRequest.Entry buildEnrollCertRequestEntry(
        String id, String profile, CertRequest certRequest)
        throws Exception;

    protected abstract EnrollCertRequest.EnrollType getCmpReqType()
        throws Exception;

    protected EnrollCertResult enroll() throws Exception {
      EnrollCertRequest.EnrollType type = getCmpReqType();

      if (extkeyusages != null) {
        List<String> list = new ArrayList<>(extkeyusages.size());
        for (String m : extkeyusages) {
          String id = Completers.ExtKeyusageCompleter.getIdForUsageName(m);
          if (id == null) {
            try {
              new ASN1ObjectIdentifier(m).getId();
            } catch (Exception ex) {
              throw new IllegalCmdParamException(
                  "invalid extended key usage " + m);
            }
          }
        }

        extkeyusages = list;
      }

      X500Name subjectDn = new X500Name(subject);
      List<RDN> list = new LinkedList<>();

      if (StringUtil.isNotBlank(dateOfBirth)) {
        ASN1ObjectIdentifier id = OIDs.DN.dateOfBirth;
        RDN[] rdns = subjectDn.getRDNs(id);

        if (rdns == null || rdns.length == 0) {
          Instant date = DateUtil.parseUtcTimeyyyyMMdd(dateOfBirth)
              .plus(12, ChronoUnit.HOURS);

          ASN1Encodable atvValue = new DERGeneralizedTime(
              DateUtil.toUtcTimeyyyyMMddhhmmss(date) + "Z");

          RDN rdn = new RDN(id, atvValue);
          list.add(rdn);
        }
      }

      if (CollectionUtil.isNotEmpty(postalAddress)) {
        ASN1ObjectIdentifier id = OIDs.DN.postalAddress;
        RDN[] rdns = subjectDn.getRDNs(id);

        if (rdns == null || rdns.length == 0) {
          ASN1EncodableVector vec = new ASN1EncodableVector();
          for (String m : postalAddress) {
            vec.add(new DERUTF8String(m));
          }

          if (vec.size() > 0) {
            ASN1Sequence atvValue = new DERSequence(vec);
            RDN rdn = new RDN(id, atvValue);
            list.add(rdn);
          }
        }
      }

      if (!list.isEmpty()) {
        Collections.addAll(list, subjectDn.getRDNs());
        subjectDn = new X500Name(list.toArray(new RDN[0]));
      }

      CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
      certTemplateBuilder.setSubject(subjectDn);

      SubjectPublicKeyInfo publicKey = getPublicKey();
      if (publicKey != null) {
        certTemplateBuilder.setPublicKey(publicKey);
      }

      if (StringUtil.isNotBlank(notBeforeS)
          || StringUtil.isNotBlank(notAfterS)) {
        Time notBefore = StringUtil.isNotBlank(notBeforeS)
            ? new Time(Date.from(
                DateUtil.parseUtcTimeyyyyMMddhhmmss(notBeforeS)))
            : null;

        Time notAfter = StringUtil.isNotBlank(notAfterS)
            ? new Time(Date.from(
                DateUtil.parseUtcTimeyyyyMMddhhmmss(notAfterS)))
            : null;

        OptionalValidity validity = new OptionalValidity(notBefore, notAfter);
        certTemplateBuilder.setValidity(validity);
      }

      // SubjectAltNames
      List<Extension> extensions = new LinkedList<>();
      if (isNotEmpty(subjectAltNames)) {
        extensions.add(X509Util.createExtnSubjectAltName(
            subjectAltNames, false));
      }

      // SubjectInfoAccess
      if (isNotEmpty(subjectInfoAccesses)) {
        extensions.add(X509Util.createExtnSubjectInfoAccess(
            subjectInfoAccesses, false));
      }

      // Keyusage
      if (isNotEmpty(keyusages)) {
        Set<KeyUsage> usages = new HashSet<>();
        for (String usage : keyusages) {
          usages.add(KeyUsage.getKeyUsage(usage));
        }
        org.bouncycastle.asn1.x509.KeyUsage extValue =
            X509Util.createKeyUsage(usages);
        ASN1ObjectIdentifier extType = OIDs.Extn.keyUsage;
        extensions.add(new Extension(extType, false, extValue.getEncoded()));
      }

      // ExtendedKeyusage
      if (isNotEmpty(extkeyusages)) {
        ExtendedKeyUsage extValue = X509Util.createExtendedUsage(
            textToAsn1ObjectIdentifers(extkeyusages));

        extensions.add(new Extension(OIDs.Extn.extendedKeyUsage,
            false, extValue.getEncoded()));
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

            MonetaryValue monterayValue =
                new MonetaryValue(currency, amount, exponent);
            QCStatement statement = new QCStatement(
                OIDs.QCS.id_etsi_qcs_QcLimitValue, monterayValue);
            vec.add(statement);
          } catch (Exception ex) {
            throw new Exception("invalid qc-eu-limit '" + m + "'");
          }
        }

        ASN1ObjectIdentifier extType = OIDs.Extn.qCStatements;
        ASN1Sequence extValue = new DERSequence(vec);
        extensions.add(new Extension(extType, false, extValue.getEncoded()));
      }

      // biometricInfo
      if (biometricType != null && biometricHashAlgo != null
          && biometricFile != null) {
        TypeOfBiometricData objBiometricType =
            StringUtil.isNumber(biometricType)
                ? new TypeOfBiometricData(Integer.parseInt(biometricType))
                : new TypeOfBiometricData(
                    new ASN1ObjectIdentifier(biometricType));

        HashAlgo objBiometricHashAlgo = getHashAlgo(biometricHashAlgo);
        byte[] biometricBytes = IoUtil.read(biometricFile);
        byte[] biometricDataHash = objBiometricHashAlgo.hash(biometricBytes);

        DERIA5String sourceDataUri = null;
        if (biometricUri != null) {
          sourceDataUri = new DERIA5String(biometricUri);
        }
        BiometricData biometricData = new BiometricData(objBiometricType,
            objBiometricHashAlgo.getAlgorithmIdentifier(),
            new DEROctetString(biometricDataHash), sourceDataUri);

        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(biometricData);

        ASN1ObjectIdentifier extType = OIDs.Extn.biometricInfo;
        ASN1Sequence extValue = new DERSequence(vec);
        extensions.add(new Extension(extType, false, extValue.getEncoded()));
      } else if (biometricType == null && biometricHashAlgo == null
          && biometricFile == null) {
        // Do nothing
      } else {
        throw new Exception("either all of biometric triples (type, " +
            "hash algo, file) must be set or none of them should be set");
      }

      List<ASN1ObjectIdentifier> addedExtnTypes =
          new ArrayList<>(extensions.size());
      for (Extension extn : extensions) {
        addedExtnTypes.add(extn.getExtnId());
      }

      // extra extensions
      if (extensionsFile != null) {
        Extensions extns = Extensions.getInstance(IoUtil.read(extensionsFile));
        for (ASN1ObjectIdentifier extnId : extns.getExtensionOIDs()) {
          if (addedExtnTypes.contains(extnId)) {
            throw new Exception("duplicated extension " + extnId.getId());
          }

          Extension extn = extns.getExtension(extnId);
          extensions.add(extn);
          addedExtnTypes.add(extnId);
        }
      }

      if (isNotEmpty(extensions)) {
        Extensions asn1Extensions =
            new Extensions(extensions.toArray(new Extension[0]));
        certTemplateBuilder.setExtensions(asn1Extensions);
      }

      CertRequest certReq = new CertRequest(1, certTemplateBuilder.build(),
          null);

      EnrollCertRequest.Entry reqEntry = buildEnrollCertRequestEntry(
          "id-1", profile, certReq);
      EnrollCertRequest request = new EnrollCertRequest(type);
      request.addRequestEntry(reqEntry);

      ReqRespDebug debug = getReqRespDebug();
      EnrollCertResult result;
      try {
        result = client.enrollCerts(caName, getRequestor(), request, debug);
      } finally {
        saveRequestResponse(debug);
      }

      return result;
    } // method enroll

    static List<ASN1ObjectIdentifier> textToAsn1ObjectIdentifers(
        List<String> oidTexts) {
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
    } // method textToAsn1ObjectIdentifers

  } // class EnrollAction

  public abstract static class EnrollCertAction extends EnrollAction {

    @Option(name = "--cmpreq-type", description =
        "CMP request type (ir for Initialization Request,\n" +
        "cr for Certification Request, and ccr for Cross-Certification " +
            "Request)")
    @Completion(value = StringsCompleter.class, values = {"ir", "cr", "ccr"})
    private String cmpreqType = "cr";

    @Option(name = "--outform", description =
        "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Option(name = "--rsa-pss", description =
        "whether to use the RSAPSS for the POP computation\n"
        + "(only applied to RSA key)")
    private Boolean rsaPss = Boolean.FALSE;

    protected SignAlgoMode getSignAlgoMode() {
      return rsaPss != null && rsaPss ? SignAlgoMode.RSAPSS : null;
    }

    protected abstract ConcurrentContentSigner getSigner()
        throws ObjectCreationException, CmpClientException;

    @Override
    protected SubjectPublicKeyInfo getPublicKey() throws Exception {
      return getSigner().getCertificate().getSubjectPublicKeyInfo();
    }

    @Override
    protected EnrollCertRequest.Entry buildEnrollCertRequestEntry(
        String id, String profile, CertRequest certRequest)
            throws Exception {
      ConcurrentContentSigner signer = getSigner();

      ProofOfPossessionSigningKeyBuilder popBuilder =
          new ProofOfPossessionSigningKeyBuilder(certRequest);
      XiContentSigner signer0 = signer.borrowSigner();
      POPOSigningKey popSk;
      try {
        popSk = popBuilder.build(signer0);
      } finally {
        signer.requiteSigner(signer0);
      }

      ProofOfPossession pop = new ProofOfPossession(popSk);
      return new EnrollCertRequest.Entry(id, profile, certRequest, pop);
    } // method buildEnrollCertRequestEntry

    @Override
    protected Object execute0() throws Exception {
      EnrollCertResult result = enroll();

      CertifiedKeyPairOrError certOrError = null;

      if (result != null) {
        String id = result.getAllIds().iterator().next();
        certOrError = result.getCertOrError(id);
      }

      if (certOrError == null) {
        throw new CmdFailure("error, received neither certificate nor error");
      } else if (certOrError.getError() != null) {
        throw new CmdFailure(certOrError.getError().toString());
      }

      saveVerbose("saved certificate to file", outputFile,
          encodeCert(certOrError.getCertificate().getEncoded(), outform));

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
    } // method getCmpReqType

  } // class EnrollCertAction

}
