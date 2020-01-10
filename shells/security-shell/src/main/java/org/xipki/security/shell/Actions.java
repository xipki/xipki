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

package org.xipki.security.shell;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
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
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.xipki.password.OBFPasswordService;
import org.xipki.password.PBEAlgo;
import org.xipki.password.PBEPasswordService;
import org.xipki.security.BadInputException;
import org.xipki.security.ConcurrentBagEntrySigner;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DHSigStaticKeyCertPair;
import org.xipki.security.EdECConstants;
import org.xipki.security.ExtensionExistence;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeyUsage;
import org.xipki.security.NoIdleSignerException;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.Xipki;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignatureAlgoControl;
import org.xipki.security.X509ExtensionType;
import org.xipki.security.X509ExtensionType.ExtensionsType;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.Completers.ExtensionNameCompleter;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.CompareUtil;
import org.xipki.util.DateUtil;
import org.xipki.util.Hex;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import com.alibaba.fastjson.JSON;

/**
 * Security actions.
 *
 * @author Lijun Liao
 */

public class Actions {

  @Command(scope = "xi", name = "cert-info", description = "print certificate information")
  @Service
  public static class CertInfo extends SecurityAction {

    @Option(name = "--in", description = "certificate file")
    @Completion(FileCompleter.class)
    private String inFile;

    @Option(name = "--hex", aliases = "-h", description = "print hex number")
    private Boolean hex = Boolean.FALSE;

    @Option(name = "--serial", description = "print serial number")
    private Boolean serial;

    @Option(name = "--subject", description = "print subject")
    private Boolean subject;

    @Option(name = "--issuer", description = "print issuer")
    private Boolean issuer;

    @Option(name = "--not-before", description = "print notBefore")
    private Boolean notBefore;

    @Option(name = "--not-after", description = "print notAfter")
    private Boolean notAfter;

    @Option(name = "--fingerprint", description = "print fingerprint in hex")
    private Boolean fingerprint;

    @Option(name = "--hash", description = "hash algorithm name")
    @Completion(Completers.HashAlgCompleter.class)
    protected String hashAlgo = "SHA256";

    @Override
    protected Object execute0() throws Exception {
      Certificate cert = X509Util.parseBcCert(IoUtil.read(inFile));

      if (serial != null && serial) {
        return getNumber(cert.getSerialNumber().getPositiveValue());
      } else if (subject != null && subject) {
        return cert.getSubject().toString();
      } else if (issuer != null && issuer) {
        return cert.getIssuer().toString();
      } else if (notBefore != null && notBefore) {
        return toUtcTimeyyyyMMddhhmmssZ(cert.getStartDate().getDate());
      } else if (notAfter != null && notAfter) {
        return toUtcTimeyyyyMMddhhmmssZ(cert.getEndDate().getDate());
      } else if (fingerprint != null && fingerprint) {
        byte[] encoded = cert.getEncoded();
        return HashAlgo.getInstance(hashAlgo).hexHash(encoded);
      }

      return null;
    }

    private String getNumber(Number no) {
      if (!hex) {
        return no.toString();
      }

      if (no instanceof Byte) {
        return "0x" + Hex.encode(new byte[]{(byte) no});
      } else if (no instanceof Short) {
        return "0x" + Integer.toHexString(Integer.valueOf((short) no));
      } else if (no instanceof Integer) {
        return "0x" + Integer.toHexString((int) no);
      } else if (no instanceof Long) {
        return "0x" + Long.toHexString((long) no);
      } else if (no instanceof Long) {
        return "0x" + Long.toHexString((long) no);
      } else if (no instanceof BigInteger) {
        return "0x" + ((BigInteger) no).toString(16);
      } else {
        return no.toString();
      }
    }

  } // class CertInfo

  @Command(scope = "xi", name = "convert-keystore", description = "Convert keystore")
  @Service
  public static class ConvertKeystore extends SecurityAction {

    @Option(name = "--in", required = true, description = "source keystore file")
    @Completion(FileCompleter.class)
    private String inFile;

    @Option(name = "--intype", required = true, description = "type of the source keystore")
    @Completion(SecurityCompleters.KeystoreTypeCompleter.class)
    private String inType;

    @Option(name = "--inpwd", description = "password of the source keystore")
    private String inPwd;

    @Option(name = "--out", required = true, description = "destination keystore file")
    @Completion(FileCompleter.class)
    private String outFile;

    @Option(name = "--outtype", required = true, description = "type of the destination keystore")
    @Completion(SecurityCompleters.KeystoreTypeCompleter.class)
    private String outType;

    @Option(name = "--outpwd", description = "password of the destination keystore")
    private String outPwd;

    @Override
    protected Object execute0() throws Exception {
      File realInFile = new File(IoUtil.expandFilepath(inFile));
      File realOutFile = new File(IoUtil.expandFilepath(outFile));

      if (CompareUtil.equalsObject(realInFile, realOutFile)) {
        throw new IllegalCmdParamException("in and out cannot be the same");
      }

      KeyStore inKs = KeyStore.getInstance(inType);
      KeyStore outKs = KeyStore.getInstance(outType);
      outKs.load(null);

      char[] inPassword = readPasswordIfNotSet("password of the source keystore", inPwd);
      InputStream inStream = Files.newInputStream(realInFile.toPath());
      try {
        inKs.load(inStream, inPassword);
      } finally {
        inStream.close();
      }

      char[] outPassword = readPasswordIfNotSet("password of the destination keystore", outPwd);
      Enumeration<String> aliases = inKs.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (inKs.isKeyEntry(alias)) {
          java.security.cert.Certificate[] certs = inKs.getCertificateChain(alias);
          Key key = inKs.getKey(alias, inPassword);
          outKs.setKeyEntry(alias, key, outPassword, certs);
        } else {
          java.security.cert.Certificate cert = inKs.getCertificate(alias);
          outKs.setCertificateEntry(alias, cert);
        }
      }

      ByteArrayOutputStream bout = new ByteArrayOutputStream(4096);
      outKs.store(bout, outPassword);
      saveVerbose("saved destination keystore to file", realOutFile, bout.toByteArray());
      return null;
    }

  } // class ConvertKeystore

  @Command(scope = "xi", name = "crl-info", description = "print CRL information")
  @Service
  public static class CrlInfo extends SecurityAction {

    @Option(name = "--in", description = "CRL file")
    @Completion(FileCompleter.class)
    private String inFile;

    @Option(name = "--hex", aliases = "-h", description = "print hex number")
    private Boolean hex = Boolean.FALSE;

    @Option(name = "--crlnumber", description = "print CRL number")
    private Boolean crlNumber;

    @Option(name = "--issuer", description = "print issuer")
    private Boolean issuer;

    @Option(name = "--this-update", description = "print thisUpdate")
    private Boolean thisUpdate;

    @Option(name = "--next-update", description = "print nextUpdate")
    private Boolean nextUpdate;

    @Override
    protected Object execute0() throws Exception {
      CertificateList crl = CertificateList.getInstance(
          X509Util.toDerEncoded(IoUtil.read(inFile)));

      if (crlNumber != null && crlNumber) {
        ASN1Encodable asn1 = crl.getTBSCertList().getExtensions().getExtensionParsedValue(
            Extension.cRLNumber);
        if (asn1 == null) {
          return "null";
        }
        return getNumber(ASN1Integer.getInstance(asn1).getPositiveValue());
      } else if (issuer != null && issuer) {
        return crl.getIssuer().toString();
      } else if (thisUpdate != null && thisUpdate) {
        return toUtcTimeyyyyMMddhhmmssZ(crl.getThisUpdate().getDate());
      } else if (nextUpdate != null && nextUpdate) {
        return crl.getNextUpdate() == null ? "null" :
          toUtcTimeyyyyMMddhhmmssZ(crl.getNextUpdate().getDate());
      }

      return null;
    }

    private String getNumber(Number no) {
      if (!hex) {
        return no.toString();
      }

      if (no instanceof Byte) {
        return "0X" + Hex.encode(new byte[]{(byte) no});
      } else if (no instanceof Short) {
        return "0X" + Integer.toHexString(Integer.valueOf((short) no));
      } else if (no instanceof Integer) {
        return "0X" + Integer.toHexString((int) no);
      } else if (no instanceof Long) {
        return "0X" + Long.toHexString((long) no);
      } else if (no instanceof Long) {
        return "0X" + Long.toHexString((long) no);
      } else if (no instanceof BigInteger) {
        return "0X" + ((BigInteger) no).toString(16);
      } else {
        return no.toString();
      }
    }

  } // class CrlInfo

  public abstract static class CsrGenAction extends SecurityAction {

    private static final long _12_HOURS_MS = 12L * 60 * 60 * 1000;

    @Option(name = "--hash", description = "hash algorithm name (will be ignored in some keys, "
        + "e.g. edwards curve based keys)")
    @Completion(Completers.HashAlgCompleter.class)
    protected String hashAlgo = "SHA256";

    @Option(name = "--subject-alt-name", aliases = "--san", multiValued = true,
        description = "subjectAltName")
    protected List<String> subjectAltNames;

    @Option(name = "--subject-info-access", aliases = "--sia", multiValued = true,
        description = "subjectInfoAccess")
    protected List<String> subjectInfoAccesses;

    @Option(name = "--peer-cert",
        description = "Peer certificate file, only for the Diffie-Hellman keys")
    @Completion(FileCompleter.class)
    private String peerCertFile;

    @Option(name = "--peer-certs", description = "Peer certificates file "
        + "(A PEM file containing certificates, only for the Diffie-Hellman keys")
    @Completion(FileCompleter.class)
    private String peerCertsFile;

    @Option(name = "--subject", aliases = "-s", required = true, description = "subject in the CSR")
    private String subject;

    @Option(name = "--dateOfBirth", description = "Date of birth YYYYMMdd in subject")
    private String dateOfBirth;

    @Option(name = "--postalAddress", multiValued = true, description = "postal address in subject")
    private List<String> postalAddress;

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
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description = "CSR file")
    @Completion(FileCompleter.class)
    private String outputFilename;

    @Option(name = "--challenge-password", aliases = "-c", description = "challenge password")
    private String challengePassword;

    @Option(name = "--keyusage", multiValued = true, description = "keyusage")
    @Completion(Completers.KeyusageCompleter.class)
    private List<String> keyusages;

    @Option(name = "--ext-keyusage", multiValued = true,
        description = "extended keyusage (name or OID)")
    @Completion(Completers.ExtKeyusageCompleter.class)
    private List<String> extkeyusages;

    @Option(name = "--qc-eu-limit", multiValued = true,
        description = "QC EuLimitValue of format <currency>:<amount>:<exponent>")
    private List<String> qcEuLimits;

    @Option(name = "--biometric-type", description = "Biometric type")
    private String biometricType;

    @Option(name = "--biometric-hash", description = "Biometric hash algorithm")
    @Completion(Completers.HashAlgCompleter.class)
    private String biometricHashAlgo;

    @Option(name = "--biometric-file", description = "Biometric hash algorithm")
    private String biometricFile;

    @Option(name = "--biometric-uri", description = "Biometric sourcedata URI")
    @Completion(FileCompleter.class)
    private String biometricUri;

    @Option(name = "--extra-extensions-file",
        description = "Configuration file for extral extensions")
    @Completion(FileCompleter.class)
    private String extraExtensionsFile;

    @Option(name = "--need-extension", multiValued = true,
        description = "types (name or OID) of extension that must be contained in the certificate")
    @Completion(Completers.ExtensionNameCompleter.class)
    private List<String> needExtensionTypes;

    @Option(name = "--want-extension", multiValued = true,
        description = "types (name or OID) of extension that should be contained in the "
                        + "certificate if possible")
    @Completion(Completers.ExtensionNameCompleter.class)
    private List<String> wantExtensionTypes;

    /**
     * Gets the signer for the give signatureAlgoControl.
     * @param signatureAlgoControl
     *          The signature control. Must not be {@code null}.
     * @return the signer
     * @throws Exception
     *           If getting signer failed.
     */
    protected abstract ConcurrentContentSigner getSigner(
         SignatureAlgoControl signatureAlgoControl) throws Exception;

    protected List<X509Certificate> getPeerCertificates()
        throws CertificateException, IOException {
      if (StringUtil.isNotBlank(peerCertsFile)) {
        try (PemReader pemReader = new PemReader(new FileReader(peerCertsFile))) {
          List<X509Certificate> certs = new LinkedList<>();
          PemObject pemObj;
          while ((pemObj = pemReader.readPemObject()) != null) {
            if (!"CERTIFICATE".equals(pemObj.getType())) {
              continue;
            }

            certs.add(X509Util.parseCert(pemObj.getContent()));
          }
          return certs.isEmpty() ? null : certs;
        }
      } else if (StringUtil.isNotBlank(peerCertFile)) {
        X509Certificate cert = X509Util.parseCert(Paths.get(peerCertFile).toFile());
        return Arrays.asList(cert);
      } else {
        return null;
      }
    } // method getPeerCertificates

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

      // SubjectAltNames
      List<Extension> extensions = new LinkedList<>();

      ASN1OctetString extnValue = isEmpty(subjectAltNames) ? null
          : X509Util.createExtnSubjectAltName(subjectAltNames, false).getExtnValue();
      if (extnValue != null) {
        ASN1ObjectIdentifier oid = Extension.subjectAlternativeName;
        extensions.add(new Extension(oid, false, extnValue));
        needExtensionTypes.add(oid.getId());
      }

      // SubjectInfoAccess
      extnValue = isEmpty(subjectInfoAccesses) ? null
          : X509Util.createExtnSubjectInfoAccess(subjectInfoAccesses, false).getExtnValue();

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
                ObjectIdentifiers.Extn.id_etsi_qcs_QcLimitValue, monterayValue);
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

      // extra extensions
      if (extraExtensionsFile != null) {
        byte[] bytes = IoUtil.read(extraExtensionsFile);
        ExtensionsType extraExtensions = JSON.parseObject(bytes, ExtensionsType.class);
        extraExtensions.validate();

        List<X509ExtensionType> extnConfs = extraExtensions.getExtensions();
        if (CollectionUtil.isNotEmpty(extnConfs)) {
          for (X509ExtensionType m : extnConfs) {
            byte[] encodedExtnValue =
                m.getConstant().toASN1Encodable().toASN1Primitive().getEncoded(ASN1Encoding.DER);
            extensions.add(new Extension(
                new ASN1ObjectIdentifier(m.getType().getOid()), false, encodedExtnValue));
          }
        }
      }

      for (Extension addExt : getAdditionalExtensions()) {
        extensions.add(addExt);
      }

      needExtensionTypes.addAll(getAdditionalNeedExtensionTypes());
      wantExtensionTypes.addAll(getAdditionalWantExtensionTypes());

      if (isNotEmpty(needExtensionTypes) || isNotEmpty(wantExtensionTypes)) {
        ExtensionExistence ee = new ExtensionExistence(
            textToAsn1ObjectIdentifers(needExtensionTypes),
            textToAsn1ObjectIdentifers(wantExtensionTypes));
        extensions.add(new Extension(ObjectIdentifiers.Xipki.id_xipki_ext_cmpRequestExtensions,
            false, ee.toASN1Primitive().getEncoded()));
      }

      ConcurrentContentSigner signer = getSigner(new SignatureAlgoControl(rsaMgf1, dsaPlain, gm));

      Map<ASN1ObjectIdentifier, ASN1Encodable> attributes = new HashMap<>();
      if (CollectionUtil.isNotEmpty(extensions)) {
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
        for (RDN rdn : subjectDn.getRDNs()) {
          list.add(rdn);
        }

        subjectDn = new X500Name(list.toArray(new RDN[0]));
      }

      PKCS10CertificationRequest csr = generateRequest(signer, subjectPublicKeyInfo, subjectDn,
          attributes);

      saveVerbose("saved CSR to file", outputFilename, encodeCsr(csr.getEncoded(), outform));
      return null;
    } // method execute0

    protected X500Name getSubject(String subjectText) {
      return new X500Name(Args.notBlank(subjectText, "subjectText"));
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

    private static List<ASN1ObjectIdentifier> textToAsn1ObjectIdentifers(List<String> oidTexts) {
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

    private PKCS10CertificationRequest generateRequest(ConcurrentContentSigner signer,
        SubjectPublicKeyInfo subjectPublicKeyInfo, X500Name subjectDn,
        Map<ASN1ObjectIdentifier, ASN1Encodable> attributes) throws XiSecurityException {
      Args.notNull(signer, "signer");
      Args.notNull(subjectPublicKeyInfo, "subjectPublicKeyInfo");
      Args.notNull(subjectDn, "subjectDn");
      PKCS10CertificationRequestBuilder csrBuilder =
          new PKCS10CertificationRequestBuilder(subjectDn, subjectPublicKeyInfo);
      if (CollectionUtil.isNotEmpty(attributes)) {
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
    } // method generateRequest

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
    } // method resolveExtensionTypes

  } // class CsrGenAction

  @Command(scope = "xi", name = "validate-csr", description = "validate CSR")
  @Service
  public static class ValidateCsr extends SecurityAction {

    @Option(name = "--csr", required = true, description = "CSR file")
    @Completion(FileCompleter.class)
    private String csrFile;

    @Option(name = "--keystore", description = "peer's keystore file")
    @Completion(FileCompleter.class)
    private String peerKeystoreFile;

    @Option(name = "--keystore-type", description = "type of the keystore")
    @Completion(SecurityCompleters.KeystoreTypeCompleter.class)
    private String keystoreType = "PKCS12";

    @Option(name = "--keystore-password", description = "password of the keystore")
    private String keystorePassword;

    @Override
    protected Object execute0() throws Exception {
      CertificationRequest csr = X509Util.parseCsr(IoUtil.read(csrFile));

      ASN1ObjectIdentifier algOid = csr.getSignatureAlgorithm().getAlgorithm();

      DHSigStaticKeyCertPair peerKeyAndCert = null;
      if (Xipki.id_alg_dhPop_x25519_sha256.equals(algOid)
          || Xipki.id_alg_dhPop_x448_sha512.equals(algOid)) {
        if (peerKeystoreFile == null || keystorePassword == null) {
          System.err.println("could not verify CSR, please specify the peer's keystore");
          return null;
        }

        String requiredKeyAlg;
        if (Xipki.id_alg_dhPop_x25519_sha256.equals(algOid)) {
          requiredKeyAlg = EdECConstants.X25519;
        } else {
          requiredKeyAlg = EdECConstants.X448;
        }

        char[] password = keystorePassword.toCharArray();
        KeyStore ks = KeyUtil.getKeyStore(keystoreType);

        File file = IoUtil.expandFilepath(new File(peerKeystoreFile));
        try (InputStream is = new FileInputStream(file)) {
          ks.load(is, password);

          Enumeration<String> aliases = ks.aliases();
          while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!ks.isKeyEntry(alias)) {
              continue;
            }

            PrivateKey key = (PrivateKey) ks.getKey(alias, password);
            if (key.getAlgorithm().equalsIgnoreCase(requiredKeyAlg)) {
              X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
              peerKeyAndCert = new DHSigStaticKeyCertPair(key, cert);
              break;
            }
          }
        }

        if (peerKeyAndCert == null) {
          System.err.println("could not find peer key entry to verify the CSR");
          return null;
        }

      }

      String sigAlgo = AlgorithmUtil.getSignatureAlgoName(csr.getSignatureAlgorithm());
      boolean bo = securityFactory.verifyPopo(csr, null, peerKeyAndCert);
      String txt = bo ? "valid" : "invalid";
      println("The POP is " + txt + " (signature algorithm " + sigAlgo + ").");
      return null;
    }

  } // method ValidateCsr

  @Command(scope = "xi", name = "deobfuscate", description = "deobfuscate password")
  @Service
  public static class Deobfuscate extends SecurityAction {

    @Option(name = "--password",
        description = "obfuscated password, starts with OBF:\n"
            + "exactly one of password and password-file must be specified")
    private String passwordHint;

    @Option(name = "--password-file", description = "file containing the obfuscated password")
    @Completion(FileCompleter.class)
    private String passwordFile;

    @Option(name = "--out", description = "where to save the password")
    @Completion(FileCompleter.class)
    private String outFile;

    @Override
    protected Object execute0() throws Exception {
      if (!(passwordHint == null ^ passwordFile == null)) {
        throw new IllegalCmdParamException(
            "exactly one of password and password-file must be specified");
      }

      if (passwordHint == null) {
        passwordHint = new String(IoUtil.read(passwordFile));
      }

      if (!StringUtil.startsWithIgnoreCase(passwordHint, "OBF:")) {
        throw new IllegalCmdParamException("encrypted password '" + passwordHint
            + "' does not start with OBF:");
      }

      String password = OBFPasswordService.deobfuscate(passwordHint);
      if (outFile != null) {
        saveVerbose("saved the password to file", outFile, StringUtil.toUtf8Bytes(password));
      } else {
        println("the password is: '" + new String(password) + "'");
      }
      return null;
    }

  } // class Deobfuscate

  @Command(scope = "xi", name = "extract-cert", description = "extract certificates from CRL")
  @Service
  public static class ExtractCert extends SecurityAction {

    @Option(name = "--crl", required = true, description = "CRL file")
    @Completion(FileCompleter.class)
    private String crlFile;

    @Option(name = "--out", aliases = "-o", required = true,
        description = "ZIP file to save the extracted certificates")
    @Completion(FileCompleter.class)
    private String outFile;

    @Override
    protected Object execute0() throws Exception {
      X509CRL crl = X509Util.parseCrl(new File(crlFile));
      String oidExtnCerts = ObjectIdentifiers.Xipki.id_xipki_ext_crlCertset.getId();
      byte[] extnValue = crl.getExtensionValue(oidExtnCerts);
      if (extnValue == null) {
        throw new IllegalCmdParamException("no certificate is contained in " + crlFile);
      }

      extnValue = removingTagAndLenFromExtensionValue(extnValue);
      ASN1Set asn1Set = DERSet.getInstance(extnValue);
      final int n = asn1Set.size();
      if (n == 0) {
        throw new CmdFailure("no certificate is contained in " + crlFile);
      }

      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ZipOutputStream zip = new ZipOutputStream(out);

      for (int i = 0; i < n; i++) {
        ASN1Encodable asn1 = asn1Set.getObjectAt(i);
        Certificate cert;
        try {
          ASN1Sequence seq = ASN1Sequence.getInstance(asn1);
          cert = Certificate.getInstance(seq.getObjectAt(0));
        } catch (IllegalArgumentException ex) {
          // backwards compatibility
          cert = Certificate.getInstance(asn1);
        }

        byte[] certBytes = cert.getEncoded();
        String sha1FpCert = HashAlgo.SHA1.hexHash(certBytes);
        ZipEntry certZipEntry = new ZipEntry(sha1FpCert + ".der");
        zip.putNextEntry(certZipEntry);
        try {
          zip.write(certBytes);
        } finally {
          zip.closeEntry();
        }
      }

      zip.flush();
      zip.close();

      saveVerbose("extracted " + n + " certificates to", outFile, out.toByteArray());
      return null;
    } // method execute0

    private static byte[] removingTagAndLenFromExtensionValue(byte[] encodedExtensionValue) {
      DEROctetString derOctet = (DEROctetString) DEROctetString.getInstance(encodedExtensionValue);
      return derOctet.getOctets();
    }

  } // class ExtractCert

  @Command(scope = "xi", name = "import-cert", description = "import certificates to a keystore")
  @Service
  public static class ImportCert extends SecurityAction {

    @Option(name = "--keystore", required = true, description = "keystore file")
    @Completion(FileCompleter.class)
    private String ksFile;

    @Option(name = "--type", required = true, description = "type of the keystore")
    @Completion(SecurityCompleters.KeystoreTypeCompleter.class)
    private String ksType;

    @Option(name = "--password", description = "password of the keystore")
    private String ksPwd;

    @Option(name = "--cert", aliases = "-c", required = true, multiValued = true,
        description = "certificate files")
    @Completion(FileCompleter.class)
    private List<String> certFiles;

    @Override
    protected Object execute0() throws Exception {
      File realKsFile = new File(IoUtil.expandFilepath(ksFile));
      KeyStore ks = KeyStore.getInstance(ksType);
      char[] password = readPasswordIfNotSet(ksPwd);

      Set<String> aliases = new HashSet<>(10);
      if (realKsFile.exists()) {
        InputStream inStream = Files.newInputStream(realKsFile.toPath());
        try {
          ks.load(inStream, password);
        } finally {
          inStream.close();
        }

        Enumeration<String> strs = ks.aliases();
        while (strs.hasMoreElements()) {
          aliases.add(strs.nextElement());
        }
      } else {
        ks.load(null);
      }

      for (String certFile : certFiles) {
        X509Certificate cert = X509Util.parseCert(new File(certFile));
        String baseAlias = X509Util.getCommonName(cert.getSubjectX500Principal());
        String alias = baseAlias;
        int idx = 2;
        while (aliases.contains(alias)) {
          alias = baseAlias + "-" + (idx++);
        }
        ks.setCertificateEntry(alias, cert);
        aliases.add(alias);
      }

      ByteArrayOutputStream bout = new ByteArrayOutputStream(4096);
      ks.store(bout, password);
      saveVerbose("saved keystore to file", realKsFile, bout.toByteArray());
      return null;
    }

  } // class ImportCert

  @Command(scope = "xi", name = "keystore-convert", description = "convert the keystore format")
  @Service
  public static class KeystoreConvert extends SecurityAction {

    @Option(name = "--in-type", required = true, description = "type of source keystore")
    private String inType;

    @Option(name = "--in", required = true, description = "file of source keystore")
    @Completion(FileCompleter.class)
    private String inFile;

    @Option(name = "--in-provider", description = "Security provider of source keystore")
    private String inProvider;

    @Option(name = "--in-pass", description = "password of source keystore")
    private String inPass;

    @Option(name = "--in-keypass-diff",
        description = "whether the password for the keys differs from that of source keystore\n"
          + "will be ignored if --in-keypass is set")
    private Boolean inKeyPassDiff = Boolean.FALSE;

    @Option(name = "--in-keypass", valueToShowInHelp = "keystore password",
        description = "password for the keys of source keystore")
    private String inKeyPass;

    @Option(name = "--out-type", required = true, description = "type of target keystore")
    private String outType;

    @Option(name = "--out-provider", description = "Security provider of target keystore")
    private String outProvider;

    @Option(name = "--out", required = true, description = "file of target keystore")
    @Completion(FileCompleter.class)
    private String outFile;

    @Option(name = "--out-pass", description = "password of target keystore")
    private String outPass;

    @Option(name = "--out-keypass-diff",
        description = "whether the password for the keys differs from that of target keystore\n"
            + "will be ignored if --out-keypass is set")
    private Boolean outKeyPassDiff = Boolean.FALSE;

    @Option(name = "--out-keypass", valueToShowInHelp = "keystore password",
        description = "password for the keys of target keystore")
    private String outKeyPass;

    @Override
    protected Object execute0() throws Exception {
      KeyStore srcKs;
      if (StringUtil.isBlank(inProvider)) {
        srcKs = KeyStore.getInstance(inType);
      } else {
        srcKs = KeyStore.getInstance(inType, inProvider);
      }

      char[] inPwd;
      if (inPass != null) {
        inPwd = inPass.toCharArray();
      } else {
        inPwd = readPassword("Enter the password of the source keystore");
      }

      srcKs.load(Files.newInputStream(Paths.get(inFile)), inPwd);
      Enumeration<String> aliases = srcKs.aliases();
      boolean containsKeyEntry = false;
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (srcKs.isKeyEntry(alias)) {
          containsKeyEntry = true;
          break;
        }
      }

      char[] inKeyPwd = null;
      if (containsKeyEntry) {
        if (inKeyPass != null) {
          inKeyPwd = inKeyPass.toCharArray();
        } else {
          if (inKeyPassDiff) {
            inKeyPwd = readPassword("Enter the password for keys of the source keystore");
          } else {
            inKeyPwd = inPwd;
          }
        }
      }

      char[] outPwd;
      if (outPass != null) {
        outPwd = outPass.toCharArray();
      } else {
        outPwd = readPassword("Enter the password of the target keystore");
      }

      char[] outKeyPwd = null;
      if (containsKeyEntry) {
        if (outKeyPass != null) {
          inKeyPwd = outKeyPass.toCharArray();
        } else {
          if (outKeyPassDiff) {
            inKeyPwd = readPassword("Enter the password for keys of the target keystore");
          } else {
            inKeyPwd = inPwd;
          }
        }
      }

      KeyStore destKs;
      if (StringUtil.isBlank(outProvider)) {
        destKs = KeyStore.getInstance(outType);
      } else {
        destKs = KeyStore.getInstance(outType, inProvider);
      }

      destKs.load(null, outPwd);

      aliases = srcKs.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (srcKs.isKeyEntry(alias)) {
          Key key = srcKs.getKey(alias, inKeyPwd);
          java.security.cert.Certificate[] chain = srcKs.getCertificateChain(alias);
          destKs.setKeyEntry(alias, key, outKeyPwd, chain);
        } else if (srcKs.isCertificateEntry(alias)) {
          java.security.cert.Certificate cert = srcKs.getCertificate(alias);
          destKs.setCertificateEntry(alias, cert);
        } else {
          println("entry " + alias + " is neither key nor certificate, ignore it");
        }
      }

      ByteArrayOutputStream bout = new ByteArrayOutputStream();

      destKs.store(bout, outPwd);

      saveVerbose("converted keystore to", outFile, bout.toByteArray());
      return null;
    } // method execute0

  } // class KeystoreConvert

  @Command(scope = "xi", name = "obfuscate", description = "obfuscate password")
  @Service
  public static class Obfuscate extends SecurityAction {

    @Option(name = "--out", description = "where to save the encrypted password")
    @Completion(FileCompleter.class)
    private String outFile;

    @Option(name = "-k", description = "quorum of the password parts")
    private Integer quorum = 1;

    @Override
    protected Object execute0() throws Exception {
      Args.range(quorum, "k", 1, 10);

      char[] password;
      if (quorum == 1) {
        password = readPassword("Password");
      } else {
        char[][] parts = new char[quorum][];
        for (int i = 0; i < quorum; i++) {
          parts[i] = readPassword("Password " + (i + 1) + "/" + quorum);
        }
        password = StringUtil.merge(parts);
      }

      String passwordHint = OBFPasswordService.obfuscate(new String(password));
      if (outFile != null) {
        saveVerbose("saved the obfuscated password to file", outFile,
            StringUtil.toUtf8Bytes(passwordHint));
      } else {
        println("the obfuscated password is: '" + passwordHint + "'");
      }
      return null;
    }

  } // class Obfuscate

  @Command(scope = "xi", name = "pbe-dec", description = "decrypt password with master password")
  @Service
  public static class PbeDec extends SecurityAction {

    @Option(name = "--password",
        description = "encrypted password, starts with PBE:\n"
            + "exactly one of password and password-file must be specified")
    private String passwordHint;

    @Option(name = "--password-file", description = "file containing the encrypted password")
    @Completion(FileCompleter.class)
    private String passwordFile;

    @Option(name = "--mpassword-file",
        description = "file containing the (obfuscated) master password")
    @Completion(FileCompleter.class)
    private String masterPasswordFile;

    @Option(name = "--mk", description = "quorum of the master password parts")
    private Integer mquorum = 1;

    @Option(name = "--out", description = "where to save the password")
    @Completion(FileCompleter.class)
    private String outFile;

    @Override
    protected Object execute0() throws Exception {
      Args.range(mquorum, "mk", 1, 10);
      if (!(passwordHint == null ^ passwordFile == null)) {
        throw new IllegalCmdParamException(
            "exactly one of password and password-file must be specified");
      }

      if (passwordHint == null) {
        passwordHint = new String(IoUtil.read(passwordFile));
      }

      if (!StringUtil.startsWithIgnoreCase(passwordHint, "PBE:")) {
        throw new IllegalCmdParamException("encrypted password '" + passwordHint
            + "' does not start with PBE:");
      }

      char[] masterPassword;
      if (masterPasswordFile != null) {
        String str = new String(IoUtil.read(masterPasswordFile));
        if (str.startsWith("OBF:") || str.startsWith("obf:")) {
          str = OBFPasswordService.deobfuscate(str);
        }
        masterPassword = str.toCharArray();
      } else {
        if (mquorum == 1) {
          masterPassword = readPassword("Master password");
        } else {
          char[][] parts = new char[mquorum][];
          for (int i = 0; i < mquorum; i++) {
            parts[i] = readPassword("Master password (part " + (i + 1) + "/" + mquorum + ")");
          }
          masterPassword = StringUtil.merge(parts);
        }
      }
      char[] password = PBEPasswordService.decryptPassword(masterPassword, passwordHint);

      if (outFile != null) {
        saveVerbose("saved the password to file", outFile,
            StringUtil.toUtf8Bytes(new String(password)));
      } else {
        println("the password is: '" + new String(password) + "'");
      }
      return null;
    } // method execute0

  } // class PbeDec

  @Command(scope = "xi", name = "pbe-enc", description = "encrypt password with master password")
  @Service
  public static class PbeEnc extends SecurityAction {

    @Option(name = "--iteration-count", aliases = "-n",
        description = "iteration count, between 1 and 65535")
    private int iterationCount = 2000;

    @Option(name = "--out", description = "where to save the encrypted password")
    @Completion(FileCompleter.class)
    private String outFile;

    @Option(name = "-k", description = "quorum of the password parts")
    private Integer quorum = 1;

    @Option(name = "--mpassword-file",
        description = "file containing the (obfuscated) master password")
    @Completion(FileCompleter.class)
    private String masterPasswordFile;

    @Option(name = "--mk", description = "quorum of the master password parts")
    private Integer mquorum = 1;

    @Override
    protected Object execute0() throws Exception {
      Args.range(iterationCount, "iterationCount", 1, 65535);
      Args.range(quorum, "k", 1, 10);
      Args.range(mquorum, "mk", 1, 10);

      char[] masterPassword;
      if (masterPasswordFile != null) {
        String str = new String(IoUtil.read(masterPasswordFile));
        if (str.startsWith("OBF:") || str.startsWith("obf:")) {
          str = OBFPasswordService.deobfuscate(str);
        }
        masterPassword = str.toCharArray();
      } else {
        if (mquorum == 1) {
          masterPassword = readPassword("Master password");
        } else {
          char[][] parts = new char[mquorum][];
          for (int i = 0; i < mquorum; i++) {
            parts[i] = readPassword("Master password (part " + (i + 1) + "/" + mquorum + ")");
          }
          masterPassword = StringUtil.merge(parts);
        }
      }

      char[] password;
      if (quorum == 1) {
        password = readPassword("Password");
      } else {
        char[][] parts = new char[quorum][];
        for (int i = 0; i < quorum; i++) {
          parts[i] = readPassword("Password (part " + (i + 1) + "/" + quorum + ")");
        }
        password = StringUtil.merge(parts);
      }

      String passwordHint = PBEPasswordService.encryptPassword(PBEAlgo.PBEWithHmacSHA256AndAES_256,
          iterationCount, masterPassword, password);
      if (outFile != null) {
        saveVerbose("saved the encrypted password to file", outFile,
            StringUtil.toUtf8Bytes(passwordHint));
      } else {
        println("the encrypted password is: '" + passwordHint + "'");
      }
      return null;
    } // method execute0

  } // class PbeEnc

  public abstract static class SecurityAction extends XiAction {

    @Reference
    protected SecurityFactory securityFactory;

    protected String toUtcTimeyyyyMMddhhmmssZ(Date date) {
      return DateUtil.toUtcTimeyyyyMMddhhmmss(date) + "Z";
    }

  } // class SecurityAction

}
