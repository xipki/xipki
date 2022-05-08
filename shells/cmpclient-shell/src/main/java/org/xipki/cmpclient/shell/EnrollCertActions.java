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

package org.xipki.cmpclient.shell;

import com.alibaba.fastjson.JSON;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.apache.karaf.shell.support.completers.StringsCompleter;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.qualified.*;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xipki.cmpclient.CmpClientException;
import org.xipki.cmpclient.EnrollCertRequest;
import org.xipki.cmpclient.EnrollCertRequest.EnrollType;
import org.xipki.cmpclient.EnrollCertResult;
import org.xipki.cmpclient.EnrollCertResult.CertifiedKeyPairOrError;
import org.xipki.cmpclient.shell.Actions.ClientAction;
import org.xipki.security.KeyUsage;
import org.xipki.security.*;
import org.xipki.security.X509ExtensionType.ExtensionsType;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.DateUtil;
import org.xipki.util.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * CMP client actions to enroll certificates.
 *
 * @author Lijun Liao
 *
 */
public class EnrollCertActions {

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
    protected Object execute0()
        throws Exception {
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

      X509Cert cert = null;
      if (result != null) {
        String id = result.getAllIds().iterator().next();
        cert = result.getCertOrError(id).getCertificate();
      }

      if (cert == null) {
        throw new CmdFailure("no certificate received from the server");
      }

      saveVerbose("certificate saved to file", outputFile, encodeCert(cert.getEncoded(), outform));
      return null;
    } // method execute0

  } // class CmpCsrEnroll

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
    protected SubjectPublicKeyInfo getPublicKey()
        throws Exception {
      return null;
    }

    @Override
    protected EnrollCertRequest.Entry buildEnrollCertRequestEntry(String id, String profile,
        CertRequest certRequest)
            throws Exception {
      final boolean caGenKeypair = true;
      final boolean kup = false;
      return new EnrollCertRequest.Entry("id-1", profile, certRequest, null, caGenKeypair, kup);
    }

    @Override
    protected Object execute0()
        throws Exception {
      EnrollCertResult result = enroll();

      X509Cert cert = null;
      PrivateKeyInfo privateKeyInfo = null;
      if (result != null) {
        String id = result.getAllIds().iterator().next();
        CertifiedKeyPairOrError certOrError = result.getCertOrError(id);
        cert = certOrError.getCertificate();
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

      X509Cert[] caCertChain = result.getCaCertChain();
      int size = caCertChain == null ? 1 : 1 + caCertChain.length;
      X509Certificate[] certchain = new X509Certificate[size];
      certchain[0] = cert.toJceCert();
      if (size > 1) {
        for (int i = 0; i < caCertChain.length; i++) {
          certchain[i + 1] = caCertChain[i].toJceCert();
        }
      }

      PrivateKey privateKey = BouncyCastleProvider.getPrivateKey(privateKeyInfo);

      KeyStore ks = KeyStore.getInstance("PKCS12");
      char[] pwd = getPassword();
      ks.load(null, pwd);
      ks.setKeyEntry("main", privateKey, pwd, certchain);
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      ks.store(bout, pwd);
      saveVerbose("saved key to file", p12OutputFile, bout.toByteArray());

      return null;
    } // method execute0

    @Override
    protected EnrollType getCmpReqType()
        throws Exception {
      if ("cr".equalsIgnoreCase(cmpreqType)) {
        return EnrollCertRequest.EnrollType.CERT_REQ;
      } else if ("ir".equalsIgnoreCase(cmpreqType)) {
        return EnrollCertRequest.EnrollType.INIT_REQ;
      } else {
        throw new IllegalCmdParamException("invalid cmpreq-type " + cmpreqType);
      }
    } // method getCmpReqType

    private char[] getPassword()
        throws IOException {
      char[] pwdInChar = readPasswordIfNotSet(password);
      if (pwdInChar != null) {
        password = new String(pwdInChar);
      }
      return pwdInChar;
    } // method getPassword

  } // class CmpEnrollCagenkey

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
    protected ConcurrentContentSigner getSigner()
        throws ObjectCreationException {
      if (signer == null) {
        byte[] keyIdBytes = null;
        if (keyId != null) {
          keyIdBytes = Hex.decode(keyId);
        }

        SignerConf signerConf = getPkcs11SignerConf(moduleName, slotIndex, keyLabel,
            keyIdBytes, getHashAlgo(hashAlgo), getSignatureAlgoControl());
        signer = securityFactory.createSigner("PKCS11", signerConf, (X509Cert[]) null);
      }
      return signer;
    } // method getSigner

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
    } // method getPkcs11SignerConf

  } // class CmpEnrollP11

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
    protected ConcurrentContentSigner getSigner()
        throws ObjectCreationException, CmpClientException {
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
            getHashAlgo(hashAlgo), getSignatureAlgoControl());

        String caName = getCaName().toLowerCase();
        List<X509Cert> peerCerts = client.getDhPopPeerCertificates(caName);
        if (CollectionUtil.isNotEmpty(peerCerts)) {
          signerConf.setPeerCertificates(peerCerts);
        }

        signer = securityFactory.createSigner("PKCS12", signerConf, (X509Cert[]) null);
      }
      return signer;
    } // method getSigner

  } // class CmpEnrollP12

  public abstract static class EnrollAction extends ClientAction {

    private static final long _12_HOURS_MS = 12L * 60 * 60 * 1000;

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

    @Option(name = "--subject-alt-name", aliases = "--san", multiValued = true,
    description = "subjectAltName, in the form of [tagNo]value or [tagText]value. "
            + "Valid tagNo/tagText/value:\n"
            + " '0'/'othername'/OID=[DirectoryStringChoice:]value,\n"
            + "    valid DirectoryStringChoices are printableString and utf8String,\n"
            + "    default to utf8Sring"
            + " '1'/'email'/text,\n"
            + " '2'/'dns'/text,\n"
            + " '4'/'dirName'/X500 name e.g. CN=abc,\n"
            + " '5'/'edi'/key=value,\n"
            + " '6'/'uri'/text,\n"
            + " '7'/'ip'/IP address,\n"
            + " '8'/'rid'/OID")
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

    @Option(name = "--dateOfBirth", description = "Date of birth YYYYMMdd in subject")
    private String dateOfBirth;

    @Option(name = "--postalAddress", multiValued = true, description = "postal address in subject")
    private List<String> postalAddress;

    @Option(name = "--extra-extensions-file",
        description = "Configuration file for extral extensions")
    @Completion(FileCompleter.class)
    private String extraExtensionsFile;

    protected abstract SubjectPublicKeyInfo getPublicKey()
        throws Exception;

    protected abstract EnrollCertRequest.Entry buildEnrollCertRequestEntry(
        String id, String profile, CertRequest certRequest)
            throws Exception;

    protected abstract EnrollCertRequest.EnrollType getCmpReqType()
        throws Exception;

    protected String getCaName()
        throws CmpClientException {
      if (StringUtil.isBlank(caName)) {
        caName = client.getCaNameForProfile(profile);
      }

      return caName;
    }

    protected EnrollCertResult enroll()
        throws Exception {
      // CHECKSTYLE:SKIP
      EnrollCertRequest.EnrollType type = getCmpReqType();

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

      X500Name subjectDn = new X500Name(subject);
      List<RDN> list = new LinkedList<RDN>();

      if (StringUtil.isNotBlank(dateOfBirth)) {
        ASN1ObjectIdentifier id = ObjectIdentifiers.DN.dateOfBirth;
        RDN[] rdns = subjectDn.getRDNs(id);

        if (rdns == null || rdns.length == 0) {
          Date date = DateUtil.parseUtcTimeyyyyMMdd(dateOfBirth);
          date = new Date(date.getTime() + _12_HOURS_MS);
          ASN1Encodable atvValue = new DERGeneralizedTime(
              DateUtil.toUtcTimeyyyyMMddhhmmss(date) + "Z");
          RDN rdn = new RDN(id, atvValue);
          list.add(rdn);
        }
      }

      if (CollectionUtil.isNotEmpty(postalAddress)) {
        ASN1ObjectIdentifier id = ObjectIdentifiers.DN.postalAddress;
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
      }

      // SubjectInfoAccess
      if (isNotEmpty(subjectInfoAccesses)) {
        extensions.add(X509Util.createExtnSubjectInfoAccess(subjectInfoAccesses, false));
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
      }

      // ExtendedKeyusage
      if (isNotEmpty(extkeyusages)) {
        ExtendedKeyUsage extValue = X509Util.createExtendedUsage(
            textToAsn1ObjectIdentifers(extkeyusages));
        ASN1ObjectIdentifier extType = Extension.extendedKeyUsage;
        extensions.add(new Extension(extType, false, extValue.getEncoded()));
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
                ObjectIdentifiers.Extn.id_etsi_qcs_QcLimitValue, monterayValue);
            vec.add(statment);
          } catch (Exception ex) {
            throw new Exception("invalid qc-eu-limit '" + m + "'");
          }
        }

        ASN1ObjectIdentifier extType = Extension.qCStatements;
        ASN1Sequence extValue = new DERSequence(vec);
        extensions.add(new Extension(extType, false, extValue.getEncoded()));
      }

      // biometricInfo
      if (biometricType != null && biometricHashAlgo != null && biometricFile != null) {
        TypeOfBiometricData objBiometricType = StringUtil.isNumber(biometricType)
            ? new TypeOfBiometricData(Integer.parseInt(biometricType))
            : new TypeOfBiometricData(new ASN1ObjectIdentifier(biometricType));

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

        ASN1ObjectIdentifier extType = Extension.biometricInfo;
        ASN1Sequence extValue = new DERSequence(vec);
        extensions.add(new Extension(extType, false, extValue.getEncoded()));
      } else if (biometricType == null && biometricHashAlgo == null && biometricFile == null) {
        // Do nothing
      } else {
        throw new Exception("either all of biometric triples (type, hash algo, file)"
            + " must be set or none of them should be set");
      }

      // extra extensions
      if (extraExtensionsFile != null) {
        byte[] bytes = IoUtil.read(extraExtensionsFile);
        ExtensionsType extraExtensions = JSON.parseObject(bytes, ExtensionsType.class);
        extraExtensions.validate();

        List<X509ExtensionType> extnConfs = extraExtensions.getExtensions();
        if (CollectionUtil.isNotEmpty(extnConfs)) {
          for (X509ExtensionType m : extnConfs) {
            String id = m.getType().getOid();
            byte[] encodedExtnValue =
                m.getConstant().toASN1Encodable().toASN1Primitive().getEncoded(ASN1Encoding.DER);
            extensions.add(new Extension(new ASN1ObjectIdentifier(id), false, encodedExtnValue));
          }
        }
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
        result = client.enrollCerts(getCaName(), request, debug);
      } finally {
        saveRequestResponse(debug);
      }

      return result;
    } // method enroll

    static List<ASN1ObjectIdentifier> textToAsn1ObjectIdentifers(List<String> oidTexts) {
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

    @Option(name = "--cmpreq-type",
        description = "CMP request type (ir for Initialization Request,\n"
            + "cr for Certification Request, and ccr for Cross-Certification Request)")
    @Completion(value = StringsCompleter.class, values = {"ir", "cr", "ccr"})
    private String cmpreqType = "cr";

    @Option(name = "--hash", description = "hash algorithm name for the POP computation")
    protected String hashAlgo = "SHA256";

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Option(name = "--rsa-pss",
        description = "whether to use the RSAPSS for the POP computation\n"
            + "(only applied to RSA key)")
    private Boolean rsaPss = Boolean.FALSE;

    @Option(name = "--dsa-plain",
        description = "whether to use the Plain DSA for the POP computation\n"
            + "(only applied to DSA and ECDSA key)")
    private Boolean dsaPlain = Boolean.FALSE;

    @Option(name = "--gm",
        description = "whether to use the chinese GM algorithm for the POP computation\n"
            + "(only applied to EC key with GM curves)")
    private Boolean gm = Boolean.FALSE;

    protected SignatureAlgoControl getSignatureAlgoControl() {
      return new SignatureAlgoControl(rsaPss, dsaPlain, gm);
    }

    protected abstract ConcurrentContentSigner getSigner()
        throws ObjectCreationException, CmpClientException;

    @Override
    protected SubjectPublicKeyInfo getPublicKey()
        throws Exception {
      return getSigner().getCertificate().getSubjectPublicKeyInfo();
    }

    @Override
    protected EnrollCertRequest.Entry buildEnrollCertRequestEntry(String id, String profile,
        CertRequest certRequest)
            throws Exception {
      ConcurrentContentSigner signer = getSigner();

      ProofOfPossessionSigningKeyBuilder popBuilder =
          new ProofOfPossessionSigningKeyBuilder(certRequest);
      ConcurrentBagEntrySigner signer0 = signer.borrowSigner();
      POPOSigningKey popSk;
      try {
        popSk = popBuilder.build(signer0.value());
      } finally {
        signer.requiteSigner(signer0);
      }

      ProofOfPossession pop = new ProofOfPossession(popSk);
      return new EnrollCertRequest.Entry(id, profile, certRequest, pop);
    } // method buildEnrollCertRequestEntry

    @Override
    protected Object execute0()
        throws Exception {
      EnrollCertResult result = enroll();

      X509Cert cert = null;
      if (result != null) {
        String id = result.getAllIds().iterator().next();
        cert = result.getCertOrError(id).getCertificate();
      }

      if (cert == null) {
        throw new CmdFailure("no certificate received from the server");
      }

      saveVerbose("saved certificate to file", outputFile, encodeCert(cert.getEncoded(), outform));

      return null;
    } // method execute0

    @Override
    protected EnrollType getCmpReqType()
        throws Exception {
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
