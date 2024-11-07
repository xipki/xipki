// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.EdECConstants;
import org.xipki.security.SignatureAlgoControl;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs12.KeyStoreWrapper;
import org.xipki.security.pkcs12.KeypairWithCert;
import org.xipki.security.pkcs12.KeystoreGenerationParameters;
import org.xipki.security.pkcs12.P12KeyGenerator;
import org.xipki.security.shell.SecurityActions.CsrGenAction;
import org.xipki.security.shell.SecurityActions.SecurityAction;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.Args;
import org.xipki.util.ConfPairs;
import org.xipki.util.IoUtil;
import org.xipki.util.PemEncoder;
import org.xipki.util.PemEncoder.PemLabel;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.ObjectCreationException;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * Actions for PKCS#12 security.
 *
 * @author Lijun Liao (xipki)
 */

public class P12Actions {

  @Command(scope = "xi", name = "secretkey-p12", description = "generate secret key in JCEKS (not PKCS#12) keystore")
  @Service
  public static class SecretkeyP12 extends P12KeyGenAction {

    @Option(name = "--key-type", required = true,
        description = "keytype, current only AES, DES3 and GENERIC are supported")
    @Completion(SecurityCompleters.SecretKeyTypeCompleter.class)
     private String keyType;

    @Option(name = "--key-size", required = true, description = "keysize in bit")
    private Integer keysize;

    @Override
    protected Object execute0() throws Exception {
      if (!StringUtil.orEqualsIgnoreCase(keyType, "AES", "DES3", "GENERIC")) {
        throw new IllegalCmdParamException("invalid keyType " + keyType);
      }

      KeyStoreWrapper key = new P12KeyGenerator().generateSecretKey(
          keyType.toUpperCase(), keysize, getKeyGenParameters());
      saveKey(key);

      return null;
    }

  } // class SecretkeyP12

  @Command(scope = "xi", name = "export-cert-p12", description = "export certificate from PKCS#12 keystore")
  @Service
  public static class ExportCertP12 extends P12SecurityAction {

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outFile;

    @Override
    protected Object execute0() throws Exception {
      KeyStore ks = getInKeyStore();

      String keyname = null;
      Enumeration<String> aliases = ks.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (ks.isKeyEntry(alias)) {
          keyname = alias;
          break;
        }
      }

      if (keyname == null) {
        throw new CmdFailure("could not find private key");
      }

      X509Certificate cert = (X509Certificate) ks.getCertificate(keyname);
      saveVerbose("saved certificate to file", outFile, encodeCert(cert.getEncoded(), outform));

      return null;
    }

  } // class ExportCertP12

  @Command(scope = "xi", name = "update-cert-p12", description = "update certificate in PKCS#12 keystore")
  @Service
  public static class UpdateCertP12 extends P12SecurityAction {

    @Option(name = "--cert", required = true, description = "certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Option(name = "--ca-cert", multiValued = true, description = "CA Certificate file")
    @Completion(FileCompleter.class)
    private Set<String> caCertFiles;

    @Override
    protected Object execute0() throws Exception {
      KeyStore inKs = getInKeyStore();

      char[] pwd = getPassword();
      X509Cert newCert = X509Util.parseCert(new File(certFile));

      assertMatch(inKs, newCert, new String(pwd));

      String keyname = null;
      Enumeration<String> aliases = inKs.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (inKs.isKeyEntry(alias)) {
          keyname = alias;
          break;
        }
      }

      if (keyname == null) {
        throw new XiSecurityException("could not find private key");
      }

      Key key = inKs.getKey(keyname, pwd);
      Set<X509Cert> caCerts = new HashSet<>();
      if (isNotEmpty(caCertFiles)) {
        for (String caCertFile : caCertFiles) {
          caCerts.add(X509Util.parseCert(new File(caCertFile)));
        }
      }
      X509Cert[] certChain = X509Util.buildCertPath(newCert, caCerts);
      Certificate[] jceCertChain = new Certificate[certChain.length];
      for (int i = 0; i < certChain.length; i++) {
        jceCertChain[i] = certChain[i].toJceCert();
      }

      KeyStore outKs = KeyUtil.getOutKeyStore("PKCS12");
      outKs.load(null, null);

      aliases = inKs.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (alias.equalsIgnoreCase(keyname)) {
          outKs.setKeyEntry(keyname, key, pwd, jceCertChain);
        } else {
          if (inKs.isKeyEntry(alias)) {
            outKs.setKeyEntry(alias, inKs.getKey(alias, pwd), pwd, inKs.getCertificateChain(alias));
          } else {
            outKs.setCertificateEntry(alias, inKs.getCertificate(alias));
          }
        }
      }

      try (OutputStream out = Files.newOutputStream(Paths.get(expandFilepath(p12File)))) {
        outKs.store(out, pwd);
        println("updated certificate");
        return null;
      }
    } // method execute0

    private void assertMatch(KeyStore ks, X509Cert cert, String password)
        throws Exception {
      String keyAlgName = cert.getPublicKey().getAlgorithm();
      if (StringUtil.orEqualsIgnoreCase(keyAlgName, EdECConstants.X25519, EdECConstants.X448, "XDH")) {
        // cannot be checked via creating dummy signature, just compare the public keys
        char[] pwd = password.toCharArray();
        KeypairWithCert kp = KeypairWithCert.fromKeystore(ks, null, pwd, null);
        byte[] expectedEncoded = kp.getPublicKey().getEncoded();
        byte[] encoded = cert.getPublicKey().getEncoded();
        if (!Arrays.equals(expectedEncoded, encoded)) {
          throw new XiSecurityException("the certificate and private do not match");
        }
      } else {
        ConfPairs pairs = new ConfPairs("keystore", "file:" + expandFilepath(p12File));
        pairs.putPair("parallelism", "1");
        if (password != null) {
          pairs.putPair("password", password);
        }

        SignerConf conf = new SignerConf(pairs.getEncoded(), null);
        securityFactory.createSigner("PKCS12", conf, cert);
      }
    } // method assertMatch

  } // class UpdateCertP12

  @Command(scope = "xi", name = "csr-p12", description = "generate CSR with PKCS#12 keystore")
  @Service
  public static class CsrP12 extends CsrGenAction {

    @Option(name = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FileCompleter.class)
    private String p12File;

    @Option(name = "--password", description = "password of the PKCS#12 keystore file, as plaintext or PBE-encrypted.")
    private String passwordHint;

    private char[] getPassword() throws IOException, PasswordResolverException {
      char[] pwdInChar = readPasswordIfNotSet("Enter the keystore password", passwordHint);
      if (pwdInChar != null) {
        passwordHint = new String(pwdInChar);
      }
      return pwdInChar;
    }

    public KeyStore getKeyStore()
        throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException,
        PasswordResolverException {
      KeyStore ks;
      try (InputStream in = Files.newInputStream(Paths.get(expandFilepath(p12File)))) {
        ks = KeyUtil.getInKeyStore("PKCS12");
        ks.load(in, getPassword());
      }
      return ks;
    }

    @Override
    protected ConcurrentContentSigner getSigner() throws ObjectCreationException, NoSuchAlgorithmException {
      SignatureAlgoControl signatureAlgoControl = getSignatureAlgoControl();
      char[] pwd;
      try {
        pwd = getPassword();
      } catch (IOException | PasswordResolverException ex) {
        throw new ObjectCreationException("could not read password: " + ex.getMessage(), ex);
      }

      ConfPairs conf = new ConfPairs("password", new String(pwd))
          .putPair("parallelism", Integer.toString(1))
          .putPair("keystore", "file:" + p12File);

      SignerConf signerConf = new SignerConf(conf.getEncoded(), null, signatureAlgoControl);
      try {
        signerConf.setPeerCertificates(getPeerCertificates());
      } catch (CertificateException | IOException ex) {
        throw new ObjectCreationException("error getting peer certificates", ex);
      }
      return securityFactory.createSigner("PKCS12", signerConf, (X509Cert[]) null);
    } // method getSigner

  } // class CsrP12

  @Command(scope = "xi", name = "dsa-p12", description = "generate RSA keypair in PKCS#12 keystore")
  @Service
  public static class DsaP12 extends P12KeyGenAction {

    @Option(name = "--subject", aliases = "-s", description = "subject of the self-signed certificate")
    private String subject;

    @Option(name = "--plen", description = "bit length of the prime")
    private Integer plen = 2048;

    @Option(name = "--qlen", description = "bit length of the sub-prime")
    private Integer qlen;

    @Override
    protected Object execute0() throws Exception {
      if (plen % 1024 != 0) {
        throw new IllegalCmdParamException("plen is not multiple of 1024: " + plen);
      }

      if (qlen == null) {
        qlen = (plen <= 1024) ? 160 : ((plen <= 2048) ? 224 : 256);
      }

      saveKey(new P12KeyGenerator().generateDSAKeypair(plen, qlen, getKeyGenParameters(), subject));

      return null;
    } // method execute0

  } // class DsaP12

  @Command(scope = "xi", name = "ec-p12", description = "generate EC keypair in PKCS#12 keystore")
  @Service
  public static class EcP12 extends P12KeyGenAction {

    @Option(name = "--subject", aliases = "-s", description = "subject of the self-signed certificate")
    protected String subject;

    @Option(name = "--curve", description = "EC curve name or OID")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName = "secp256r1";

    @Override
    protected Object execute0() throws Exception {
      P12KeyGenerator keyGen = new P12KeyGenerator();
      KeystoreGenerationParameters keyGenParams = getKeyGenParameters();

      ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(curveName);
      KeyStoreWrapper keypair = (curveOid != null)
          ? keyGen.generateEdECKeypair(curveOid, keyGenParams, subject)
          : keyGen.generateECKeypair(AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName),
          keyGenParams, subject);

      saveKey(keypair);

      return null;
    }

  } // class EcP12

  public abstract static class P12KeyGenAction extends SecurityAction {

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the key")
    @Completion(FileCompleter.class)
    protected String keyOutFile;

    @Option(name = "--password", description = "password of the keystore file, as plaintext or PBE-encrypted.")
    protected String passwordHint;

    protected void saveKey(KeyStoreWrapper keyGenerationResult) throws IOException {
      saveVerbose("saved PKCS#12 keystore to file", keyOutFile,
          Args.notNull(keyGenerationResult, "keyGenerationResult").keystore());
    }

    protected KeystoreGenerationParameters getKeyGenParameters() throws IOException, PasswordResolverException {
      KeystoreGenerationParameters params = new KeystoreGenerationParameters(getPassword());

      SecureRandom random = securityFactory.getRandom4Key();
      if (random != null) {
        params.setRandom(random);
      }

      return params;
    }

    private char[] getPassword() throws IOException, PasswordResolverException {
      char[] pwdInChar = readPasswordIfNotSet("Enter the keystore password", passwordHint);
      if (pwdInChar != null) {
        passwordHint = new String(pwdInChar);
      }
      return pwdInChar;
    }

  } // class P12KeyGenAction

  @Command(scope = "xi", name = "rsa-p12", description = "generate RSA keypair in PKCS#12 keystore")
  @Service
  public static class RsaP12 extends P12KeyGenAction {

    @Option(name = "--subject", aliases = "-s", description = "subject of the self-signed certificate")
    private String subject;

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize = 2048;

    @Option(name = "-e", description = "public exponent")
    private String publicExponent = SecurityActions.TEXT_F4;

    @Override
    protected Object execute0() throws Exception {
      if (keysize % 1024 != 0) {
        throw new IllegalCmdParamException("keysize is not multiple of 1024: " + keysize);
      }

      saveKey(new P12KeyGenerator().generateRSAKeypair(
          keysize, toBigInt(publicExponent), getKeyGenParameters(), subject));
      return null;
    }

  } // class RsaP12

  public abstract static class P12SecurityAction extends SecurityAction {

    @Option(name = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FileCompleter.class)
    protected String p12File;

    @Option(name = "--password", description = "password of the PKCS#12 file, as plaintext or PBE-encrypted.")
    protected String passwordHint;

    protected char[] getPassword() throws IOException, PasswordResolverException {
      char[] pwdInChar = readPasswordIfNotSet("Enter the keystore password", passwordHint);
      if (pwdInChar != null) {
        passwordHint = new String(pwdInChar);
      }
      return pwdInChar;
    }

    protected KeyStore getInKeyStore()
        throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException,
        PasswordResolverException {
      try (InputStream in = Files.newInputStream(Paths.get(expandFilepath(p12File)))) {
        KeyStore ks = KeyUtil.getInKeyStore("PKCS12");
        ks.load(in, getPassword());
        return ks;
      }
    }

  } // class P12SecurityAction

  @Command(scope = "xi", name = "sm2-p12", description = "generate SM2 (curve sm2p256v1) keypair in PKCS#12 keystore")
  @Service
  public static class Sm2P12 extends P12KeyGenAction {

    @Option(name = "--subject", aliases = "-s", description = "subject of the self-signed certificate")
    protected String subject;

    @Override
    protected Object execute0() throws Exception {
      saveKey(new P12KeyGenerator().generateECKeypair(
          GMObjectIdentifiers.sm2p256v1, getKeyGenParameters(), subject));
      return null;
    }

  } // class Sm2P12

  @Command(scope = "xi", name = "pkcs12", description = "export PKCS#12 key store, like the 'openssl pkcs12' command")
  @Service
  public static class Pkcs12 extends P12SecurityAction {

    @Option(name = "--key-out", required = true, description = "where to save the key")
    @Completion(FileCompleter.class)
    private String keyOutFile;

    @Option(name = "--cert-out", required = true, description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String certOutFile;

    @Override
    protected Object execute0() throws Exception {
      char[] password = getPassword();
      try (InputStream keystoreStream = Files.newInputStream(Paths.get(expandFilepath(p12File)))) {
        KeypairWithCert kp = KeypairWithCert.fromKeystore("PKCS12",
                              keystoreStream, password, null, password, (X509Cert) null);
        byte[] encodedKey = PemEncoder.encode(kp.getKey().getEncoded(), PemLabel.PRIVATE_KEY);
        byte[] encodedCert = PemEncoder.encode(kp.getCertificateChain()[0].getEncoded(), PemLabel.CERTIFICATE);
        IoUtil.save(keyOutFile, encodedKey);
        IoUtil.save(certOutFile, encodedCert);
      }
      return null;
    }

  } // class Pkcs12

}
