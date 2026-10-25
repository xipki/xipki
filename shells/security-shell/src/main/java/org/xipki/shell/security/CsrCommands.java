// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.security;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.GenerationException;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.pkix.asn1.est.ChangeSubjectName;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.XipkiOIDs;
import org.xipki.pkix.asn1.pkcs10.CertificationRequest;
import org.xipki.pkix.asn1.x500.DirectoryString;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.Attribute;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.pkix.asn1.x509.Extensions;
import org.xipki.pkix.asn1.x509.GeneralNames;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.codec.Hex;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.pkix.SecurityFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.KemEncapKey;
import org.xipki.pkix.exception.NoIdleSignerException;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.DHSigStaticKeyCertPair;
import org.xipki.pkix.cert.KeyUsage;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.CsrControl;
import org.xipki.pkix.sign.KemHmacSignature;
import org.xipki.crypto.core.SignAlgoMode;
import org.xipki.pkix.sign.Signer;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.crypto.core.EcCurveEnum;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.xi.Completers;
import org.xipki.codec.ConfPairs;
import org.xipki.pkix.util.misc.CollectionUtil;
import org.xipki.pkix.util.misc.PemEncoder;
import org.xipki.codec.util.IoUtil;
import org.xipki.pkix.util.misc.StringUtil;
import org.xipki.pkix.util.password.PasswordResolverException;
import org.xipki.pkix.util.password.Passwords;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * XiPKI CSR commands.
 *
 * @author Lijun Liao (xipki)
 */
public class CsrCommands {

  abstract static class CsrGenCommand extends SecurityCommands.SecurityCommand {

    @Option(names = {"--subject-alt-name", "--san"}, description = "subjectAltName entries")
    private List<String> subjectAltNames;

    @Option(names = {"--subject-info-access", "--sia"}, description = "subjectInfoAccess entries")
    private List<String> subjectInfoAccesses;

    @Option(names = "--cert", description = "certificate file to copy subject/extensions from")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(names = "--cert-ext-exclude", split = ",",
        description = "extension OIDs excluded from --cert copy")
    private List<String> excludeCertExtns;

    @Option(names = "--cert-ext-include", split = ",",
        description = "extension OIDs included from --cert copy")
    private List<String> includeCertExtns;

    @Option(names = "--old-cert", description = "certificate file to update")
    @Completion(FilePathCompleter.class)
    private String oldCertFile;

    @Option(names = {"--subject", "-s"}, description = "subject in the CSR")
    private String subject;

    @Option(names = "--outform", description = "output format of the CSR")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, required = true, description = "CSR file")
    @Completion(FilePathCompleter.class)
    private String outputFilename;

    @Option(names = {"--challenge-password", "-c"}, description = "challenge password")
    private String challengePasswordHint;

    @Option(names = "--keyusage", split = ",", description = "keyusage")
    @Completion(Completers.KeyUsageCompleter.class)
    private List<String> keyusages;

    @Option(names = "--ext-keyusage", split = ",", description = "extended keyusage")
    private List<String> extkeyusages;

    @Option(names = "--extensions-file", description = "DER-encoded Extensions file")
    @Completion(FilePathCompleter.class)
    private String extensionsFile;

    protected abstract ConcurrentSigner getSigner() throws Exception;

    protected List<X509Cert> getPeerCertificates() throws Exception {
      CsrControl control = securities().securityFactory().csrControl();
      return control == null ? null : control.peerCerts();
    }

    protected List<Extension> getAdditionalExtensions()  {
      return Collections.emptyList();
    }

    protected X500Name getSubject(String subjectText) {
      return new X500Name(Args.notBlank(subjectText, "subjectText"));
    }

    protected KemEncapKey getKemEncapKey(SubjectPublicKeyInfo myPublicKey)
        throws GenerationException {
      try {
        SecurityFactory securityFactory = securities().securityFactory();
        return securityFactory.csrControl().generateKemEncapKey(
            myPublicKey, securityFactory.random4Sign());
      } catch (Exception ex) {
        throw new GenerationException("error computing EncapKey: " + ex.getMessage(), ex);
      }
    }

    @Override
    public void run() {
      try {
        if (certFile != null && oldCertFile != null) {
          throw new IllegalArgumentException("maximal one of cert and old-cert is allowed");
        }

        ConcurrentSigner signer = getSigner();
        SubjectPublicKeyInfo subjectPublicKeyInfo = signer.x509Cert() == null
            ? KeyUtil.createSubjectPublicKeyInfo(signer.publicKey())
            : signer.x509Cert().subjectPublicKeyInfo();

        if (extkeyusages != null) {
          List<String> list = new ArrayList<>(extkeyusages.size());
          for (String usage : extkeyusages) {
            String id = getExtKeyusageOid(usage);
            if (id == null) {
              new Asn1Oid(usage);
              list.add(usage);
            } else {
              list.add(id);
            }
          }
          extkeyusages = list;
        }

        List<Extension> extensions = new LinkedList<>();
        if (CollectionUtil.isNotEmpty(subjectInfoAccesses)) {
          Extension extn = X509Util.createExtnSubjectInfoAccess(
              normalizeSubjectInfoAccesses(unescapeStructuredValues(subjectInfoAccesses)), false);
          extensions.add(extn);
        }

        if (CollectionUtil.isNotEmpty(keyusages)) {
          List<org.xipki.pkix.asn1.x509.KeyUsage> usages = new LinkedList<>();
          for (String usage : keyusages) {
            usages.add(KeyUsage.getKeyUsage(usage).asn1());
          }
          extensions.add(Extension.ofKeyUsage(false,
              new org.xipki.pkix.asn1.x509.KeyUsage(usages)));
        }

        if (CollectionUtil.isNotEmpty(extkeyusages)) {
          extensions.add(Extension.ofExtendedKeyUsage(false,
              X509Util.createExtendedUsage(textToAsn1Oids(extkeyusages))));
        }

        List<Asn1Oid> addedExtnTypes = new ArrayList<>(extensions.size());
        for (Extension extn : extensions) {
          addedExtnTypes.add(extn.getExtnId());
        }

        if (extensionsFile != null) {
          Extensions extns = Extensions.fromEncoded(IoUtil.read(extensionsFile));
          for (Asn1Oid extnId : extns.getExtensionIds()) {
            if (addedExtnTypes.contains(extnId)) {
              throw new IOException("duplicated extension " + extnId.getId());
            }
            extensions.add(extns.getExtension(extnId));
            addedExtnTypes.add(extnId);
          }
        }

        extensions.addAll(getAdditionalExtensions());
        char[] challengePassword = StringUtil.isBlank(challengePasswordHint)
            ? null : Passwords.resolvePassword(challengePasswordHint);

        if (certFile != null) {
          Certificate cert = Certificate.fromEncoded(X509Util.toDerEncoded(IoUtil.read(certFile)));
          if (!Arrays.equals(subjectPublicKeyInfo.getEncoded(),
              cert.getSubjectPublicKeyInfo().getEncoded())) {
            throw new IOException("public key extracted from signer differs from certificate");
          }

          Extensions certExtns = cert.getTBSCertificate().getExtensions();
          List<Asn1Oid> stdExcludeOids = Arrays.asList(
              ExtensionOIDs.authorityKeyIdentifier, ExtensionOIDs.authorityInfoAccess,
              ExtensionOIDs.certificateIssuer, ExtensionOIDs.certificatePolicies,
              ExtensionOIDs.cRLDistributionPoints, ExtensionOIDs.freshestCRL,
              ExtensionOIDs.nameConstraints, ExtensionOIDs.policyMappings,
              ExtensionOIDs.policyConstraints, ExtensionOIDs.certificatePolicies,
              ExtensionOIDs.subjectInfoAccess, ExtensionOIDs.subjectDirectoryAttributes);

          for (Asn1Oid certExtnOid : certExtns.getExtensionIds()) {
            boolean add = !addedExtnTypes.contains(certExtnOid);
            if (add) {
              add = CollectionUtil.isNotEmpty(includeCertExtns)
                  ? includeCertExtns.contains(certExtnOid.getId())
                  : !stdExcludeOids.contains(certExtnOid);
            }
            if (add && CollectionUtil.isNotEmpty(excludeCertExtns)) {
              add = !excludeCertExtns.contains(certExtnOid.getId());
            }
            if (add) {
              extensions.add(certExtns.getExtension(certExtnOid));
            }
          }

          CertificationRequest csr = generateRequest(
              signer, subjectPublicKeyInfo, cert.getSubject(), challengePassword, extensions);
          saveVerbose("saved CSR to file", outputFilename, derPemEncode(
              csr.getEncoded(), outform, PemEncoder.PemLabel.CERTIFICATE_REQUEST));
          return;
        }

        boolean updateOldCert = oldCertFile != null;
        X500Name newSubjectDn = null;
        if (subject == null) {
          if (!updateOldCert) {
            X509Cert signerCert = signer.x509Cert();
            if (signerCert == null) {
              throw new IllegalArgumentException("subject must be set");
            }
            newSubjectDn = signerCert.subject();
          }
        } else {
          newSubjectDn = getSubject(subject);
        }

        Extension newSubjectAltNames = null;
        if (CollectionUtil.isNotEmpty(subjectAltNames)) {
          newSubjectAltNames = X509Util.createExtnSubjectAltName(
                          unescapeStructuredValues(subjectAltNames), false);
        }

        Attribute attrChangeSubjectName = null;
        X500Name subjectDn;
        if (updateOldCert) {
          Certificate oldCert = Certificate.fromEncoded(
              X509Util.toDerEncoded(IoUtil.read(oldCertFile)));
          subjectDn = oldCert.getSubject();
          Extension oldSan = oldCert.getTBSCertificate().getExtensions()
              .getExtension(ExtensionOIDs.subjectAlternativeName);
          if (oldSan != null) {
            extensions.add(oldSan);
          }

          if (newSubjectDn != null || newSubjectAltNames != null) {
            X500Name subject = newSubjectDn == null ? subjectDn : newSubjectDn;

            GeneralNames subjectAlt = (newSubjectAltNames != null)
                ? newSubjectAltNames.getSubjectAlternativeName()
                : (oldSan == null) ? null : oldSan.getSubjectAlternativeName();

            ChangeSubjectName change = new ChangeSubjectName(subject, subjectAlt);
            attrChangeSubjectName = Attribute.ofChangeSubjectName(change);
          }
        } else {
          subjectDn = newSubjectDn;
          if (newSubjectAltNames != null) {
            extensions.add(newSubjectAltNames);
          }
        }

        CertificationRequest csr = generateRequest(
            signer, subjectPublicKeyInfo, subjectDn, challengePassword, extensions,
            attrChangeSubjectName);
        saveVerbose("saved CSR to file", outputFilename, derPemEncode(
            csr.getEncoded(), outform, PemEncoder.PemLabel.CERTIFICATE_REQUEST));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private CertificationRequest generateRequest(
        ConcurrentSigner signer, SubjectPublicKeyInfo subjectPublicKeyInfo, X500Name subjectDn,
        char[] challengePassword, List<Extension> extensions, Attribute... attrs)
        throws XiSecurityException {
      Args.notNull(signer, "signer");
      Args.notNull(subjectPublicKeyInfo, "subjectPublicKeyInfo");
      Args.notNull(subjectDn, "subjectDn");

      List<Attribute> attributes = new ArrayList<>(2);
      if (CollectionUtil.isNotEmpty(extensions)) {
        attributes.add(Attribute.ofExtensionRequest(new Extensions(extensions)));
      }
      if (challengePassword != null && challengePassword.length > 0) {
        attributes.add(Attribute.ofChallengePassword(
            new DirectoryString(new Asn1PrintableString(new String(challengePassword)))));
      }

      CertificationRequest.CsrBuilder csrBuilder =
          new CertificationRequest.CsrBuilder(subjectDn, subjectPublicKeyInfo);

      Signer signer0;
      try {
        for (Attribute entry : attributes) {
          csrBuilder.setAttribute(entry);
        }

        if (attrs != null) {
          for (Attribute attr : attrs) {
            if (attr != null) {
              csrBuilder.setAttribute(attr);
            }
          }
        }
      } catch (GenerationException ex) {
        throw new XiSecurityException(ex.getMessage(), ex);
      }

      try {
        signer0 = signer.borrowSigner();
      } catch (NoIdleSignerException ex) {
        throw new XiSecurityException(ex.getMessage(), ex);
      }

      try {
        return csrBuilder.build(signer0.x509Signer());
      } catch (SignatureException ex) {
        throw new XiSecurityException(ex.getMessage(), ex);
      } finally {
        signer.requiteSigner(signer0);
      }
    }

    private static List<Asn1Oid> textToAsn1Oids(List<String> oidTexts) {
      if (oidTexts == null) {
        return null;
      }
      List<Asn1Oid> ret = new ArrayList<>(oidTexts.size());
      for (String oidText : oidTexts) {
        if (oidText.isEmpty()) {
          continue;
        }
        Asn1Oid oid = new Asn1Oid(oidText);
        if (!ret.contains(oid)) {
          ret.add(oid);
        }
      }
      return ret;
    }

    private static List<String> normalizeSubjectInfoAccesses(List<String> accesses) {
      List<String> normalized = new ArrayList<>(accesses.size());
      for (String access : accesses) {
        int idx = access.indexOf('=');
        if (idx <= 0 || idx == access.length() - 1) {
          normalized.add(access);
          continue;
        }

        String method = access.substring(0, idx);
        String location = access.substring(idx + 1);
        normalized.add(escapeConfPairsToken(method) + "=" + escapeConfPairsToken(location));
      }
      return normalized;
    }

    private static List<String> unescapeStructuredValues(List<String> values) {
      List<String> ret = new ArrayList<>(values.size());
      for (String value : values) {
        ret.add(unescapeStructuredValue(value));
      }
      return ret;
    }

    private static String unescapeStructuredValue(String text) {
      StringBuilder sb = new StringBuilder(text.length());
      boolean escaped = false;
      for (int i = 0; i < text.length(); i++) {
        char ch = text.charAt(i);
        if (escaped) {
          sb.append(ch);
          escaped = false;
        } else if (ch == '\\') {
          escaped = true;
        } else {
          sb.append(ch);
        }
      }

      if (escaped) {
        sb.append('\\');
      }
      return sb.toString();
    }

    private static String escapeConfPairsToken(String text) {
      StringBuilder sb = new StringBuilder(text.length() + 8);
      for (int i = 0; i < text.length(); i++) {
        char ch = text.charAt(i);
        if (ch == '\\' || ch == ',' || ch == '=') {
          sb.append('\\');
        }
        sb.append(ch);
      }
      return sb.toString();
    }

    private static String getExtKeyusageOid(String usage) {
      switch (usage.toLowerCase()) {
        case "serverauth":
          return "1.3.6.1.5.5.7.3.1";
        case "clientauth":
          return "1.3.6.1.5.5.7.3.2";
        case "codesigning":
          return "1.3.6.1.5.5.7.3.3";
        case "emailprotection":
          return "1.3.6.1.5.5.7.3.4";
        case "timestamping":
          return "1.3.6.1.5.5.7.3.8";
        case "ocspsigning":
          return "1.3.6.1.5.5.7.3.9";
        default:
          return null;
      }
    }
  }

  @Command(name = "csr-jce", description = "generate CSR request with JCE device",
      mixinStandardHelpOptions = true)
  static class CsrJceCommand extends CsrGenCommand {

    @Option(names = "--type", required = true, description = "JCE signer type")
    @Completion(Completers.KeystoreTypeCompleter.class)
    private String type;

    @Option(names = "--alias", required = true, description = "alias of the key in the JCE device")
    private String alias;

    @Option(names = "--algo", required = true, description = "signature algorithm")
    @Completion(Completers.SigAlgoCompleter.class)
    private String algo;

    @Override
    protected ConcurrentSigner getSigner() throws Exception {
      SecurityFactory securityFactory = securities().securityFactory();
      SignerConf conf = new SignerConf(new ConfPairs()
          .putPair("parallelism", "1")
          .putPair("alias", alias)
          .putPair("algo", SignAlgo.getInstance(algo).jceName()));
      return securityFactory.createSigner(type, conf, (X509Cert) null);
    }
  }

  @Command(name = "csr-p11", description = "generate CSR request with PKCS#11 device",
      mixinStandardHelpOptions = true)
  static class CsrP11Command extends CsrGenCommand {

    @Option(names = "--slot", description = "slot index")
    private String slotIndex = "0";

    @Option(names = "--id", description = "id (hex) of the private key in the PKCS#11 device")
    private String id;

    @Option(names = "--label", description = "label of the private key in the PKCS#11 device")
    private String label;

    @Option(names = "--module", description = "name of the PKCS#11 module")
    @Completion(SecurityCompleters.P11ModuleNameCompleter.class)
    private String moduleName = "default";

    @Option(names = "--rsa-pss", description = "whether to use RSAPSS for POP")
    private Boolean rsaPss = Boolean.FALSE;

    @Override
    protected ConcurrentSigner getSigner() throws Exception {
      byte[] idBytes = id == null ? null : Hex.decode(id);
      if (idBytes == null && label == null) {
        throw new IllegalArgumentException("at least one of keyId and keyLabel may not be null");
      }

      SignerConf conf = new SignerConf().setParallelism(1).setSlot(Integer.parseInt(slotIndex));
      if (StringUtil.isNotBlank(moduleName)) {
        conf.setModule(moduleName);
      }
      if (idBytes != null) {
        conf.setKeyId(idBytes);
      }
      if (label != null) {
        conf.setKeyLabel(label);
      }
      if (Boolean.TRUE.equals(rsaPss)) {
        conf.setMode(SignAlgoMode.RSAPSS);
      }
      conf.setPeerCertificates(getPeerCertificates());
      return securities().securityFactory().createSigner("PKCS11", conf, (X509Cert) null);
    }
  }

  @Command(name = "csr-p12", description = "generate CSR with PKCS#12 keystore",
      mixinStandardHelpOptions = true)
  static class CsrP12Command extends CsrGenCommand {

    @Option(names = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FilePathCompleter.class)
    private String p12File;

    @Option(names = "--password", description = "password of the PKCS#12 keystore file")
    private String passwordHint;

    @Option(names = "--rsa-pss", description = "whether to use RSAPSS for POP")
    private Boolean rsaPss = Boolean.FALSE;

    private char[] getPassword() throws IOException, PasswordResolverException {
      return readPasswordIfNotSet("Enter the keystore password", passwordHint);
    }

    @Override
    protected ConcurrentSigner getSigner() throws GenerationException {
      try {
        SignerConf conf = new SignerConf()
            .setPassword(new String(getPassword())).setParallelism(1)
            .setKeystore("file:" + p12File);
        if (Boolean.TRUE.equals(rsaPss)) {
          conf.setMode(SignAlgoMode.RSAPSS);
        }
        conf.setPeerCertificates(getPeerCertificates());
        return securities().securityFactory().createSigner("PKCS12", conf, (X509Cert) null);
      } catch (IOException | PasswordResolverException ex) {
        throw new GenerationException("could not read password: " + ex.getMessage(), ex);
      } catch (GenerationException ex) {
        throw ex;
      } catch (Exception ex) {
        throw new GenerationException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "validate-csr", description = "validate CSR", mixinStandardHelpOptions = true)
  static class ValidateCsrCommand extends SecurityCommands.SecurityCommand {

    @Option(names = "--csr", required = true, description = "CSR file")
    @Completion(FilePathCompleter.class)
    private String csrFile;

    @Option(names = "--keystore", description = "peer's keystore file")
    @Completion(FilePathCompleter.class)
    private String keystoreFile;

    @Option(names = "--keystore-type", description = "type of the keystore")
    @Completion(SecurityCompleters.KeystoreTypeCompleter.class)
    private String keystoreType = "PKCS12";

    @Option(names = "--keystore-password", description = "password of the keystore")
    private String keystorePasswordHint;

    @Override
    public void run() {
      try {
        byte[] encoded = X509Util.toDerEncoded(IoUtil.read(csrFile));
        CertificationRequest csr = X509Util.parseCsr(encoded);
        Asn1Oid sigAlgOid = csr.getSignatureAlgorithm().getAlgorithm();

        boolean isKemMac = XipkiOIDs.id_alg_KEM_HMAC_SHA256.equals(sigAlgOid);
        boolean isXdh = XipkiOIDs.id_alg_dhPop_x25519.equals(sigAlgOid)
            || XipkiOIDs.id_alg_dhPop_x448.equals(sigAlgOid);

        if ((isKemMac || isXdh) && (keystoreFile == null || keystorePasswordHint == null)) {
          throw new IllegalArgumentException(
              "please specify --keystore and --keystore-password for this CSR type");
        }

        DHSigStaticKeyCertPair peerKeyAndCert = null;
        SecretKey peerMasterKey = null;

        if (isKemMac) {
          KemHmacSignature kemHmacSig = KemHmacSignature.decode(csr.signature());
          peerMasterKey = readSecretKeyFromKeystore(
              keystoreFile, kemHmacSig.id(), keystorePasswordHint);
          if (peerMasterKey == null) {
            throw new IOException("could not find peer KEM key entry to verify the CSR");
          }
        } else if (isXdh) {
          if (!StringUtil.orEqualsIgnoreCase(keystoreType, "PKCS12", "PKCS#12")) {
            throw new IllegalArgumentException("keystoreType is not PKCS12: " + keystoreType);
          }

          EcCurveEnum requiredKeyAlg = XipkiOIDs.id_alg_dhPop_x25519.equals(sigAlgOid)
              ? EcCurveEnum.X25519 : EcCurveEnum.X448;

          char[] password = Passwords.resolvePassword(keystorePasswordHint);
          File file = IoUtil.expandFilepath(new File(keystoreFile));
          try (InputStream is = Files.newInputStream(file.toPath())) {
            Pkcs12KeyStore ks = KeyUtil.loadPKCS12KeyStore(is, password);
            Set<String> aliases = ks.aliases();
            for (String alias : aliases) {
              if (!ks.isKeyEntry(alias)) {
                continue;
              }

              PrivateKeyInfo keyInfo = ks.getKey(alias);
              if (requiredKeyAlg == EcCurveEnum.ofOid(
                  keyInfo.getPrivateKeyAlgorithm().getAlgorithm())) {
                PrivateKey key = KeyInfoUtil.getPrivateKey(keyInfo);
                peerKeyAndCert = new DHSigStaticKeyCertPair(key,
                                    new X509Cert(ks.getCertificate(alias)));
                break;
              }
            }
          }

          if (peerKeyAndCert == null) {
            throw new IOException("could not find peer key entry to verify the CSR");
          }
        }

        boolean valid = securities().securityFactory().verifyPop(
            csr, null, peerKeyAndCert, peerMasterKey);
        SignAlgo signAlgo = SignAlgo.getInstance(csr.getSignatureAlgorithm());
        println("The POP is " + (valid ? "" : "in") + "valid (signature algorithm "
            + signAlgo.jceName() + ").");
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private SecretKey readSecretKeyFromKeystore(
        String ksFile, String alias, String passwordHint) throws Exception {
      char[] password = Passwords.resolvePassword(passwordHint);
      try (InputStream is = Files.newInputStream(
          IoUtil.expandFilepath(new File(ksFile)).toPath())) {
        KeyStore ks = KeyUtil.loadKeyStore("JCEKS", is, password);
        if (!ks.isKeyEntry(alias)) {
          return null;
        }
        return (SecretKey) ks.getKey(alias, password);
      }
    }
  }
}
