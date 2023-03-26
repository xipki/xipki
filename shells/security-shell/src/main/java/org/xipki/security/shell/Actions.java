// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.qualified.*;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.xipki.security.KeyUsage;
import org.xipki.security.*;
import org.xipki.security.ObjectIdentifiers.Xipki;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.Base64;
import org.xipki.util.DateUtil;
import org.xipki.util.*;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.Map.Entry;

/**
 * Security actions.
 *
 * @author Lijun Liao (xipki)
 */

public class Actions {

  public static final String TEXT_F4 = "0x10001";

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
      X509Cert cert = X509Util.parseCert(IoUtil.read(inFile));

      if (serial != null && serial) {
        return getNumber(cert.getSerialNumber());
      } else if (subject != null && subject) {
        return cert.getSubject().toString();
      } else if (issuer != null && issuer) {
        return cert.getIssuer().toString();
      } else if (notBefore != null && notBefore) {
        return toUtcTimeyyyyMMddhhmmssZ(cert.getNotBefore());
      } else if (notAfter != null && notAfter) {
        return toUtcTimeyyyyMMddhhmmssZ(cert.getNotAfter());
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
        return "0x" + Integer.toHexString((short) no);
      } else if (no instanceof Integer) {
        return "0x" + Integer.toHexString((int) no);
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

    @Option(name = "--inpwd", description = "password of the source keystore, as plaintext or PBE-encrypted.")
    private String inPwdHint;

    @Option(name = "--out", required = true, description = "destination keystore file")
    @Completion(FileCompleter.class)
    private String outFile;

    @Option(name = "--outtype", required = true, description = "type of the destination keystore")
    @Completion(SecurityCompleters.KeystoreTypeWithPEMCompleter.class)
    private String outType;

    @Option(name = "--outpwd",
        description = "password of the destination keystore, as plaintext or PBE-encrypted.\n" +
        "For PEM, you may use NONE to save the private key unprotected.")
    private String outPwdHint;

    private static final byte[] CRLF = new byte[]{'\r', '\n'};

    @Override
    protected Object execute0() throws Exception {
      File realInFile = new File(IoUtil.expandFilepath(inFile));
      File realOutFile = new File(IoUtil.expandFilepath(outFile));

      if (CompareUtil.equalsObject(realInFile, realOutFile)) {
        throw new IllegalCmdParamException("in and out cannot be the same");
      }

      KeyStore inKs = KeyStore.getInstance(inType);
      KeyStore outKs;
      ByteArrayOutputStream outPemKs;
      if ("PEM".equalsIgnoreCase(outType)) {
        outPemKs = new ByteArrayOutputStream();
        outKs = null;
      } else {
        outPemKs = null;
        outKs = KeyUtil.getOutKeyStore(outType);
        outKs.load(null);
      }

      char[] inPassword = readPasswordIfNotSet("password of the source keystore", inPwdHint);
      try (InputStream inStream = Files.newInputStream(realInFile.toPath())) {
        inKs.load(inStream, inPassword);
      }

      char[] outPassword = ("PEM".equalsIgnoreCase(outType) && "NONE".equalsIgnoreCase(outPwdHint)) ? null
          : readPasswordIfNotSet("password of the destination keystore", outPwdHint);

      OutputEncryptor pemOe = null;
      if ("PEM".equalsIgnoreCase(outType) && outPassword != null) {
        JceOpenSSLPKCS8EncryptorBuilder eb = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES);
        eb.setPassword(outPassword);
        pemOe = eb.build();
      }

      Enumeration<String> aliases = inKs.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (inKs.isKeyEntry(alias)) {
          java.security.cert.Certificate[] certs = inKs.getCertificateChain(alias);
          Key key = inKs.getKey(alias, inPassword);
          if (outKs != null) {
            outKs.setKeyEntry(alias, key, outPassword, certs);
          } else {
            if (outPassword == null) {
              outPemKs.write(PemEncoder.encode(key.getEncoded(), PemEncoder.PemLabel.PRIVATE_KEY));
            } else {
              JcaPKCS8Generator gen = new JcaPKCS8Generator((PrivateKey) key, pemOe);
              PemObject po = gen.generate();
              outPemKs.write(PemEncoder.encode(po.getContent(), PemEncoder.PemLabel.ENCRYPTED_PRIVATE_KEY));
            }
            outPemKs.write(CRLF);

            for (java.security.cert.Certificate cert : certs) {
              writePemCert(outPemKs, cert);
            }
          }
        } else {
          java.security.cert.Certificate cert = inKs.getCertificate(alias);
          if (outKs != null) {
            outKs.setCertificateEntry(alias, cert);
          } else {
            writePemCert(outPemKs, cert);
          }
        }
      }

      byte[] outBytes;
      if (outPemKs == null) {
        ByteArrayOutputStream bout = new ByteArrayOutputStream(4096);
        outKs.store(bout, outPassword);
        outBytes = bout.toByteArray();
      } else {
        outBytes = outPemKs.toByteArray();
      }
      saveVerbose("saved destination keystore to file", realOutFile, outBytes);
      return null;
    }

    private static void writePemCert(OutputStream out, java.security.cert.Certificate cert)
        throws CertificateEncodingException, IOException {
      out.write(PemEncoder.encode(cert.getEncoded(), PemEncoder.PemLabel.CERTIFICATE));
      out.write(CRLF);
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
      CertificateList crl = CertificateList.getInstance(X509Util.toDerEncoded(IoUtil.read(inFile)));

      if (crlNumber != null && crlNumber) {
        ASN1Encodable asn1 = crl.getTBSCertList().getExtensions().getExtensionParsedValue(Extension.cRLNumber);
        if (asn1 == null) {
          return "null";
        }
        return getNumber(ASN1Integer.getInstance(asn1).getPositiveValue());
      } else if (issuer != null && issuer) {
        return crl.getIssuer().toString();
      } else if (thisUpdate != null && thisUpdate) {
        return toUtcTimeyyyyMMddhhmmssZ(crl.getThisUpdate().getDate().toInstant());
      } else if (nextUpdate != null && nextUpdate) {
        return crl.getNextUpdate() == null ? "null" :
          toUtcTimeyyyyMMddhhmmssZ(crl.getNextUpdate().getDate().toInstant());
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
        return "0X" + Integer.toHexString((short) no);
      } else if (no instanceof Integer) {
        return "0X" + Integer.toHexString((int) no);
      } else if (no instanceof Long) {
        return "0X" + Long.toHexString((long) no);
      } else if (no instanceof BigInteger) {
        return "0X" + ((BigInteger) no).toString(16);
      } else {
        return no.toString();
      }
    }

  } // class CrlInfo

  public abstract static class CsrGenAction extends BaseCsrGenAction {
    @Option(name = "--hash", description = "hash algorithm name (will be ignored in some keys, "
            + "e.g. edwards curve based keys)")
    @Completion(Completers.HashAlgCompleter.class)
    protected String hashAlgo = "SHA256";

    @Option(name = "--rsa-pss", description = "whether to use the RSAPSS for the POP computation\n"
                    + "(only applied to RSA key)")
    private Boolean rsaPss = Boolean.FALSE;

    @Option(name = "--dsa-plain", description = "whether to use the Plain DSA for the POP computation")
    private Boolean dsaPlain = Boolean.FALSE;

    @Option(name = "--gm", description = "whether to use the chinese GM algorithm for the POP computation\n"
                    + "(only applied to EC key with GM curves)")
    private Boolean gm = Boolean.FALSE;

    protected SignatureAlgoControl getSignatureAlgoControl() {
      hashAlgo = hashAlgo.trim().toUpperCase();
      if (hashAlgo.indexOf('-') != -1) {
        hashAlgo = hashAlgo.replaceAll("-", "");
      }
      return new SignatureAlgoControl(rsaPss, dsaPlain, gm);
    }
  }

  public abstract static class BaseCsrGenAction extends SecurityAction {

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
    protected List<String> subjectAltNames;

    @Option(name = "--subject-info-access", aliases = "--sia", multiValued = true, description = "subjectInfoAccess")
    protected List<String> subjectInfoAccesses;

    @Option(name = "--peer-cert", description = "Peer certificate file, only for the Diffie-Hellman keys")
    @Completion(FileCompleter.class)
    private String peerCertFile;

    @Option(name = "--peer-certs", description = "Peer certificates file "
            + "(A PEM file containing certificates, only for the Diffie-Hellman keys")
    @Completion(FileCompleter.class)
    private String peerCertsFile;

    @Option(name = "--cert", description = "Certificate file, from which subject and extensions will be extracted.\n" +
        "Maximal one of cert and old-cert is allowed.")
    @Completion(FileCompleter.class)
    private String certFile;

    @Option(name = "--cert-ext-exclude", multiValued = true,
        description = "OIDs of extension types which are not copied from the --cert option to CSR.")
    private List<String> excludeCertExtns;

    @Option(name = "--cert-ext-include", multiValued = true,
        description = "OIDs of extension types which are copied from the --cert option to CSR.")
    private List<String> includeCertExtns;

    @Option(name = "--old-cert", description =
            "Certificate file to be updated. The subject and subjectAltNames will be copied to the CSR.\n" +
            "The subject and subject-alt-name specified here will be specified in the changeSubjectName attribute.\n" +
            "Maximal one of cert and old-cert is allowed.")
    @Completion(FileCompleter.class)
    private String oldCertFile;

    @Option(name = "--subject", aliases = "-s", description = "subject in the CSR, "
            + "if not set, use the subject in the signer's certificate ")
    private String subject;

    @Option(name = "--dateOfBirth", description = "Date of birth YYYYMMdd in subject")
    private String dateOfBirth;

    @Option(name = "--postalAddress", multiValued = true, description = "postal address in subject")
    private List<String> postalAddress;

    @Option(name = "--outform", description = "output format of the CSR")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description = "CSR file")
    @Completion(FileCompleter.class)
    private String outputFilename;

    @Option(name = "--challenge-password", aliases = "-c",
        description = "challenge password, as plaintext or PBE-encrypted.")
    private String challengePasswordHint;

    @Option(name = "--keyusage", multiValued = true, description = "keyusage")
    @Completion(Completers.KeyusageCompleter.class)
    private List<String> keyusages;

    @Option(name = "--ext-keyusage", multiValued = true, description = "extended keyusage (name or OID)")
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

    @Option(name = "--extensions-file", description = "File containing the DER-encoded Extensions.")
    @Completion(FileCompleter.class)
    private String extensionsFile;

    /**
     * Gets the signer for the give signatureAlgoControl.
     * @return the signer
     * @throws Exception
     *           If getting signer failed.
     */
    protected abstract ConcurrentContentSigner getSigner() throws Exception;

    protected List<X509Cert> getPeerCertificates() throws CertificateException, IOException {
      if (StringUtil.isNotBlank(peerCertsFile)) {
        return X509Util.parseCerts(Files.newInputStream(Paths.get(peerCertsFile)));
      } else if (StringUtil.isNotBlank(peerCertFile)) {
        X509Cert cert = X509Util.parseCert(Paths.get(peerCertFile).toFile());
        return Collections.singletonList(cert);
      } else {
        return null;
      }
    } // method getPeerCertificates

    @Override
    protected Object execute0() throws Exception {
      if (certFile != null && oldCertFile != null) {
        throw new IllegalCmdParamException("maximal one of cert and old-cert is allowed");
      }

      ConcurrentContentSigner signer = getSigner();

      SubjectPublicKeyInfo subjectPublicKeyInfo = (signer.getCertificate() == null)
          ? KeyUtil.createSubjectPublicKeyInfo(signer.getPublicKey())
          : signer.getCertificate().getSubjectPublicKeyInfo();

      if (extkeyusages != null) {
        List<String> list = new ArrayList<>(extkeyusages.size());
        for (String m : extkeyusages) {
          String id = Completers.ExtKeyusageCompleter.getIdForUsageName(m);
          if (id == null) {
            try {
              new ASN1ObjectIdentifier(m);
            } catch (Exception ex) {
              throw new IllegalCmdParamException("invalid extended key usage " + m);
            }
          }
        }

        extkeyusages = list;
      }

      List<Extension> extensions = new LinkedList<>();

      // SubjectInfoAccess
      ASN1OctetString extnValue = isEmpty(subjectInfoAccesses) ? null
              : X509Util.createExtnSubjectInfoAccess(subjectInfoAccesses, false).getExtnValue();

      if (extnValue != null) {
        extensions.add(new Extension(Extension.subjectInfoAccess, false, extnValue));
      }

      // Keyusage
      if (isNotEmpty(keyusages)) {
        Set<KeyUsage> usages = new HashSet<>();
        for (String usage : keyusages) {
          usages.add(KeyUsage.getKeyUsage(usage));
        }
        extensions.add(new Extension(Extension.keyUsage, false, X509Util.createKeyUsage(usages).getEncoded()));
      }

      // ExtendedKeyusage
      if (isNotEmpty(extkeyusages)) {
        extensions.add(new Extension(Extension.extendedKeyUsage, false,
            X509Util.createExtendedUsage(textToAsn1ObjectIdentifers(extkeyusages)).getEncoded()));
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

            MonetaryValue monterayValue =
                new MonetaryValue(currency, Integer.parseInt(amountS), Integer.parseInt(exponentS));
            QCStatement statment = new QCStatement(ObjectIdentifiers.Extn.id_etsi_qcs_QcLimitValue, monterayValue);
            vec.add(statment);
          } catch (Exception ex) {
            throw new Exception("invalid qc-eu-limit '" + m + "'");
          }
        }

        extensions.add(new Extension(Extension.qCStatements, false, new DERSequence(vec).getEncoded()));
      }

      // biometricInfo
      if (biometricType != null && biometricHashAlgo != null && biometricFile != null) {
        TypeOfBiometricData tmpBiometricType = StringUtil.isNumber(biometricType)
                ? new TypeOfBiometricData(Integer.parseInt(biometricType))
                : new TypeOfBiometricData(new ASN1ObjectIdentifier(biometricType));

        HashAlgo ha = HashAlgo.getInstance(biometricHashAlgo);
        byte[] tmpBiometricDataHash = ha.hash(IoUtil.read(biometricFile));

        DERIA5String tmpSourceDataUri = null;
        if (biometricUri != null) {
          tmpSourceDataUri = new DERIA5String(biometricUri);
        }
        BiometricData biometricData = new BiometricData(tmpBiometricType, ha.getAlgorithmIdentifier(),
                new DEROctetString(tmpBiometricDataHash), tmpSourceDataUri);

        extensions.add(new Extension(Extension.biometricInfo, false, new DERSequence(biometricData).getEncoded()));
      } else if (biometricType == null && biometricHashAlgo == null && biometricFile == null) {
        // Do nothing
      } else {
        throw new Exception("either all of biometric triples (type, hash algo, file)"
                + " must be set or none of them should be set");
      }

      List<ASN1ObjectIdentifier> addedExtnTypes = new ArrayList<>(extensions.size());
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

      extensions.addAll(getAdditionalExtensions());

      char[] challengePassword = StringUtil.isBlank(challengePasswordHint)
          ? null : resolvePassword(challengePasswordHint);

      if (certFile != null) {
        Certificate cert = Certificate.getInstance(X509Util.toDerEncoded(IoUtil.read(certFile)));
        if (!Arrays.equals(subjectPublicKeyInfo.getEncoded(), cert.getSubjectPublicKeyInfo().getEncoded())) {
          throw new IllegalCmdParamException("PublicKey extracted from signer is different than in the certificate");
        }

        Extensions certExtns = cert.getTBSCertificate().getExtensions();

        List<ASN1ObjectIdentifier> stdExcludeOids = Arrays.asList(
            Extension.authorityKeyIdentifier, Extension.authorityInfoAccess,   Extension.certificateIssuer,
            Extension.certificatePolicies,    Extension.cRLDistributionPoints, Extension.freshestCRL,
            Extension.nameConstraints,        Extension.policyMappings,        Extension.policyConstraints,
            Extension.certificatePolicies,    Extension.subjectInfoAccess,     Extension.subjectDirectoryAttributes);

        for (ASN1ObjectIdentifier certExtnOid : certExtns.getExtensionOIDs()) {
          boolean add = !addedExtnTypes.contains(certExtnOid);
          if (add) {
            add = isNotEmpty(includeCertExtns) ? includeCertExtns.contains(certExtnOid.getId())
                : !stdExcludeOids.contains(certExtnOid);
          }

          if (add && isNotEmpty(excludeCertExtns)) {
            add = !excludeCertExtns.contains(certExtnOid.getId());
          }

          if (add) {
            extensions.add(certExtns.getExtension(certExtnOid));
          }
        }

        PKCS10CertificationRequest csr = generateRequest(signer, subjectPublicKeyInfo, cert.getSubject(),
            challengePassword, extensions);
        saveVerbose("saved CSR to file", outputFilename, encodeCsr(csr.getEncoded(), outform));
        return null;
      }

      final boolean updateOldCert = oldCertFile != null;

      X500Name newSubjectDn = null;
      if (subject == null) {
        if (StringUtil.isNotBlank(dateOfBirth)) {
          throw new IllegalCmdParamException("dateOfBirth cannot be set if subject is not set");
        }

        if (CollectionUtil.isNotEmpty(postalAddress)) {
          throw new IllegalCmdParamException("postalAddress cannot be set if subject is not set");
        }

        if (!updateOldCert) {
          X509Cert signerCert = signer.getCertificate();
          if (signerCert == null) {
            throw new IllegalCmdParamException("subject must be set");
          }
          newSubjectDn = signerCert.getSubject();
        }
      } else {
        newSubjectDn = getSubject(subject);

        List<RDN> list = new LinkedList<>();

        if (StringUtil.isNotBlank(dateOfBirth)) {
          ASN1ObjectIdentifier id = ObjectIdentifiers.DN.dateOfBirth;
          RDN[] rdns = newSubjectDn.getRDNs(id);

          if (rdns == null || rdns.length == 0) {
            Instant date = DateUtil.parseUtcTimeyyyyMMdd(dateOfBirth);
            date = date.plus(12, ChronoUnit.HOURS);
            list.add(new RDN(id, new DERGeneralizedTime(DateUtil.toUtcTimeyyyyMMddhhmmss(date) + "Z")));
          }
        }

        if (CollectionUtil.isNotEmpty(postalAddress)) {
          ASN1ObjectIdentifier id = ObjectIdentifiers.DN.postalAddress;
          RDN[] rdns = newSubjectDn.getRDNs(id);

          if (rdns == null || rdns.length == 0) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (String m : postalAddress) {
              vec.add(new DERUTF8String(m));
            }

            if (vec.size() > 0) {
              list.add(new RDN(id, new DERSequence(vec)));
            }
          }
        }

        if (!list.isEmpty()) {
          Collections.addAll(list, newSubjectDn.getRDNs());
          newSubjectDn = new X500Name(list.toArray(new RDN[0]));
        }
      }

      // SubjectAltNames
      extnValue = isEmpty(subjectAltNames) ? null
          : X509Util.createExtnSubjectAltName(subjectAltNames, false).getExtnValue();
      Extension newSubjectAltNames = null;
      if (extnValue != null) {
        newSubjectAltNames = new Extension(Extension.subjectAlternativeName, false, extnValue);
      }

      Attribute attrChangeSubjectName = null;
      X500Name subjectDn;
      if (updateOldCert) {
        Certificate oldCert = Certificate.getInstance(X509Util.toDerEncoded(IoUtil.read(oldCertFile)));
        subjectDn = oldCert.getSubject();
        Extension oldSan = oldCert.getTBSCertificate().getExtensions().getExtension(Extension.subjectAlternativeName);
        if (oldSan != null) {
          extensions.add(oldSan);
        }

        if (newSubjectDn != null || newSubjectAltNames != null) {
          ASN1EncodableVector v = new ASN1EncodableVector();
          v.add(newSubjectDn == null ? subjectDn : newSubjectDn);

          GeneralNames subjectAlt = null;
          if (newSubjectAltNames != null) {
            subjectAlt = GeneralNames.getInstance(newSubjectAltNames.getExtnValue().getOctets());
          } else if (oldSan != null) {
            subjectAlt = GeneralNames.getInstance(oldSan.getParsedValue());
          }

          if (subjectAlt != null) {
            v.add(subjectAlt);
          }

          attrChangeSubjectName = new Attribute(ObjectIdentifiers.CMC.id_cmc_changeSubjectName,
              new DERSet(new DERSequence(v)));
        }
      } else {
        subjectDn = newSubjectDn;
        if (newSubjectAltNames != null) {
          extensions.add(newSubjectAltNames);
        }
      }

      PKCS10CertificationRequest csr = generateRequest(signer, subjectPublicKeyInfo, subjectDn,
              challengePassword, extensions, attrChangeSubjectName);
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

    private PKCS10CertificationRequest generateRequest(
        ConcurrentContentSigner signer, SubjectPublicKeyInfo subjectPublicKeyInfo,
        X500Name subjectDn, char[] challengePassword, List<Extension> extensions, Attribute... attrs)
            throws XiSecurityException {
      Args.notNull(signer, "signer");
      Args.notNull(subjectPublicKeyInfo, "subjectPublicKeyInfo");
      Args.notNull(subjectDn, "subjectDn");

      Map<ASN1ObjectIdentifier, ASN1Encodable> attributes = new HashMap<>();
      if (isNotEmpty(extensions)) {
        attributes.put(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
            new Extensions(extensions.toArray(new Extension[0])));
      }

      if (challengePassword != null && challengePassword.length > 0) {
        attributes.put(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
            new DERPrintableString(new String(challengePassword)));
      }

      PKCS10CertificationRequestBuilder csrBuilder =
          new PKCS10CertificationRequestBuilder(subjectDn, subjectPublicKeyInfo);
      if (CollectionUtil.isNotEmpty(attributes)) {
        for (Entry<ASN1ObjectIdentifier, ASN1Encodable> entry : attributes.entrySet()) {
          csrBuilder.addAttribute(entry.getKey(), entry.getValue());
        }
      }

      if (attrs != null) {
        for (Attribute attr : attrs) {
          if (attr != null) {
            csrBuilder.addAttribute(attr.getAttrType(), attr.getAttrValues().toArray());
          }
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

  } // class BaseCsrGenAction

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

    @Option(name = "--keystore-password", description = "password of the keystore, as plaintext or PBE-encrypted.")
    private String keystorePasswordHint;

    @Override
    protected Object execute0() throws Exception {
      CertificationRequest csr = X509Util.parseCsr(IoUtil.read(csrFile));

      ASN1ObjectIdentifier algOid = csr.getSignatureAlgorithm().getAlgorithm();

      DHSigStaticKeyCertPair peerKeyAndCert = null;
      if (Xipki.id_alg_dhPop_x25519.equals(algOid) || Xipki.id_alg_dhPop_x448.equals(algOid)) {
        if (peerKeystoreFile == null || keystorePasswordHint == null) {
          System.err.println("could not verify CSR, please specify the peer's keystore");
          return null;
        }

        String requiredKeyAlg = Xipki.id_alg_dhPop_x25519.equals(algOid) ? EdECConstants.X25519 : EdECConstants.X448;

        char[] password = readPasswordIfNotSet("Enter the keystore password", keystorePasswordHint);
        KeyStore ks = KeyUtil.getInKeyStore(keystoreType);

        File file = IoUtil.expandFilepath(new File(peerKeystoreFile));
        try (InputStream is = Files.newInputStream(file.toPath())) {
          ks.load(is, password);

          Enumeration<String> aliases = ks.aliases();
          while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!ks.isKeyEntry(alias)) {
              continue;
            }

            PrivateKey key = (PrivateKey) ks.getKey(alias, password);
            if (key.getAlgorithm().equalsIgnoreCase(requiredKeyAlg)) {
              peerKeyAndCert = new DHSigStaticKeyCertPair(key,
                  new X509Cert((X509Certificate) ks.getCertificate(alias)));
              break;
            }
          }
        }

        if (peerKeyAndCert == null) {
          System.err.println("could not find peer key entry to verify the CSR");
          return null;
        }

      }

      boolean bo = securityFactory.verifyPop(csr, null, peerKeyAndCert);
      SignAlgo signAlgo = SignAlgo.getInstance(csr.getSignatureAlgorithm());
      println("The POP is " + (bo ? "" : "in") + "valid (signature algorithm " + signAlgo.getJceName() + ").");
      return null;
    }

  } // method ValidateCsr

  @Command(scope = "xi", name = "import-cert", description = "import certificates to a keystore")
  @Service
  public static class ImportCert extends SecurityAction {

    @Option(name = "--keystore", required = true, description = "keystore file")
    @Completion(FileCompleter.class)
    private String ksFile;

    @Option(name = "--type", required = true, description = "type of the keystore")
    @Completion(SecurityCompleters.KeystoreTypeCompleter.class)
    private String ksType;

    @Option(name = "--password", description = "password of the keystore, as plaintext or PBE-encrypted.")
    private String ksPwdHint;

    @Option(name = "--cert", aliases = "-c", required = true, multiValued = true, description = "certificate files")
    @Completion(FileCompleter.class)
    private List<String> certFiles;

    @Override
    protected Object execute0() throws Exception {
      File realKsFile = new File(IoUtil.expandFilepath(ksFile));
      KeyStore ks = KeyUtil.getOutKeyStore(ksType);
      char[] password = readPasswordIfNotSet("Enter the keystore password", ksPwdHint);

      Set<String> aliases = new HashSet<>(10);
      if (realKsFile.exists()) {
        try (InputStream inStream = Files.newInputStream(realKsFile.toPath())) {
          ks.load(inStream, password);
        }

        Enumeration<String> strs = ks.aliases();
        while (strs.hasMoreElements()) {
          aliases.add(strs.nextElement());
        }
      } else {
        ks.load(null);
      }

      for (String certFile : certFiles) {
        X509Cert cert = X509Util.parseCert(new File(certFile));
        String baseAlias = X509Util.getCommonName(cert.getSubject());
        String alias = baseAlias;
        int idx = 2;
        while (aliases.contains(alias)) {
          alias = baseAlias + "-" + (idx++);
        }
        ks.setCertificateEntry(alias, cert.toJceCert());
        aliases.add(alias);
      }

      ByteArrayOutputStream bout = new ByteArrayOutputStream(4096);
      ks.store(bout, password);
      saveVerbose("saved keystore to file", realKsFile, bout.toByteArray());
      return null;
    }

  } // class ImportCert

  @Command(scope = "xi", name = "export-cert-p7m", description = "export (the first) certificate from CMS signed data")
  @Service
  public static class ExportCertP7m extends SecurityAction {

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Argument(index = 0, name = "p7m file", required = true, description = "File of the CMS signed data")
    @Completion(FileCompleter.class)
    private String p7mFile;

    @Argument(index = 1, name = "cert file", required = true, description = "File to save the certificate")
    @Completion(FileCompleter.class)
    private String certFile;

    @Override
    protected Object execute0() throws Exception {
      byte[] encodedCert = extractCertFromSignedData(IoUtil.read(p7mFile));
      saveVerbose("saved certificate to file", certFile, encodeCert(encodedCert, outform));
      return null;
    }

  } // class ExportCertP7m

  @Command(scope = "xi", name = "export-keycert-est",
      description = "export key and certificate from the response of EST's serverkeygen")
  @Service
  public static class ExportKeyCertEst extends SecurityAction {

    @Option(name = "--outform", description = "output format of the key and certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Argument(index = 0, name = "response-file", required = true, description = "File containing the response")
    @Completion(FileCompleter.class)
    private String estRespFile;

    @Argument(index = 1, name = "key-file", required = true, description = "File to save the private key")
    @Completion(FileCompleter.class)
    private String keyFile;

    @Argument(index = 2, name = "cert-file", required = true, description = "File to save the certificate")
    @Completion(FileCompleter.class)
    private String certFile;

    @Override
    protected Object execute0() throws Exception {
      try (BufferedReader reader = new BufferedReader(new FileReader(IoUtil.expandFilepath(estRespFile)))) {
        String boundary = null;

        // detect the boundary
        String line;
        while (true) {
          line = reader.readLine();
          if (line == null) {
            break;
          }

          if (line.startsWith("--")) {
            boundary = line;
            break;
          }
        }

        if (boundary == null) {
          throw new IOException("found no boundary");
        }

        Object[] blockInfo1 = readBlock(reader, boundary);
        if ((boolean) blockInfo1[0]) {
          throw new IOException("2 blocks is expected, found only 1");
        }

        Object[] blockInfo2 = readBlock(reader, boundary);
        if (!(boolean) blockInfo2[0]) {
          throw new IOException("2 blocks is expected, found more than 2");
        }

        byte[] keyBytes = null;
        byte[] certBytes = null;

        Object[][] blockInfos = new Object[][]{blockInfo1, blockInfo2};
        for (Object[] blockInfo : blockInfos) {
          String ct = (String) blockInfo[1];
          byte[] bytes = (byte[]) blockInfo[2];
          if (ct.startsWith("application/pkcs8")) {
            keyBytes = bytes;
          } else if (ct.startsWith("application/pkcs7-mime")) {
            certBytes = bytes;
          }
        }

        if (keyBytes == null) {
          throw new IOException("found no private key block");
        }

        if (certBytes == null) {
          throw new IOException("found no certificate block");
        }

        saveVerbose("private key saved to file", keyFile,
            derPemEncode(keyBytes, outform, PemEncoder.PemLabel.PRIVATE_KEY));

        byte[] rawCertBytes = extractCertFromSignedData(certBytes);
        saveVerbose("certificate saved to file", certFile, encodeCert(rawCertBytes, outform));
      }
      return null;
    }

    private static Object[] readBlock(BufferedReader reader, String boundary) throws IOException {
      StringBuilder sb = new StringBuilder();
      String line;

      String contentType = null;
      String encoding = null;
      boolean isLastBlock = false;

      boolean bodyStarted = false;
      boolean bodyFinished = false;

      while (true) {
        line = reader.readLine();
        if (line == null) {
          break;
        }

        if (bodyStarted) {
          if (line.equals(boundary)) {
            bodyFinished = true;
            // end of block
            break;
          } else if (line.equals(boundary + "--")) {
            // end of block and body
            bodyFinished = true;
            isLastBlock = true;
            break;
          }

          sb.append(line);
          sb.append("\r\n");
        } else if (line.isEmpty()) {
          bodyStarted = true;
        } else {
          if (StringUtil.startsWithIgnoreCase(line, "content-type:")) {
            contentType = line.substring("content-type:".length()).trim();
          } else if (StringUtil.startsWithIgnoreCase(line, "content-transfer-encoding:")) {
            encoding = line.substring("content-transfer-encoding:".length()).trim();
          }
        }
      }

      if (!(bodyStarted && bodyFinished)) {
        throw new IOException("invalid block");
      }

      byte[] content;
      if ("base64".equalsIgnoreCase(encoding)) {
        content = Base64.decodeFast(sb.toString());
      } else if (StringUtil.isBlank(encoding)) {
        content = sb.toString().getBytes(StandardCharsets.UTF_8);
      } else {
        throw new IOException("unknown content-transfer-encoding " + encoding);
      }

      return new Object[]{isLastBlock, contentType, content};
    }

  } // class ExportKeyCertEst

  public abstract static class SecurityAction extends XiAction {

    @Reference
    protected SecurityFactory securityFactory;

    protected String toUtcTimeyyyyMMddhhmmssZ(Instant date) {
      return DateUtil.toUtcTimeyyyyMMddhhmmss(date) + "Z";
    }

  } // class SecurityAction

  private static byte[] extractCertFromSignedData(byte[] cmsBytes) throws CmdFailure, IOException {
    ContentInfo ci = ContentInfo.getInstance(X509Util.toDerEncoded(cmsBytes));
    ASN1Set certs = SignedData.getInstance(ci.getContent()).getCertificates();
    if (certs == null || certs.size() == 0) {
      throw new CmdFailure("Found no certificate");
    }

    return certs.getObjectAt(0).toASN1Primitive().getEncoded();
  }

}
