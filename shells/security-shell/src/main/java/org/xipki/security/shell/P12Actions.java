// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.security.KeySpec;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs12.KeyStoreWrapper;
import org.xipki.security.pkcs12.KeypairWithCert;
import org.xipki.security.pkcs12.KeystoreGenerationParameters;
import org.xipki.security.shell.SecurityActions.SecurityAction;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.PemEncoder;
import org.xipki.util.extra.misc.PemEncoder.PemLabel;
import org.xipki.util.io.IoUtil;
import org.xipki.util.password.PasswordResolverException;

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

  @Command(scope = "xi", name = "secretkey-p12", description =
      "generate secret key in JCEKS (not PKCS#12) keystore")
  @Service
  public static class SecretkeyP12 extends P12KeyGenAction {

    @Option(name = "--key-type", required = true,
        description = "keytype, valid values are AES, DES3, GENERIC, SM4, ...")
    @Completion(SecurityCompleters.SecretKeyTypeCompleter.class)
     private String keyType;

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize;

    @Override
    protected Object execute0() throws Exception {
      if (keysize == null) {
        if ("DES3".equalsIgnoreCase(keyType)) {
          keysize = 192;
        } else if ("SM4".equalsIgnoreCase(keyType)) {
          keysize = 128;
        } else {
          throw new IllegalCmdParamException("key-size is not specified");
        }
      }

      KeyStoreWrapper key = KeyUtil.generateSecretKey(
          keyType.toUpperCase(), keysize, getKeyGenParameters());
      saveKey(key);

      return null;
    }

  } // class SecretkeyP12

  @Command(scope = "xi", name = "export-cert-p12",
      description = "export certificate from PKCS#12 keystore")
  @Service
  public static class ExportCertP12 extends P12SecurityAction {

    @Option(name = "--outform", description =
        "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the certificate")
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
      saveVerbose("saved certificate to file", outFile,
          encodeCert(cert.getEncoded(), outform));

      return null;
    }

  } // class ExportCertP12

  @Command(scope = "xi", name = "update-cert-p12",
      description = "update certificate in PKCS#12 keystore")
  @Service
  public static class UpdateCertP12 extends P12SecurityAction {

    @Option(name = "--cert", required = true, description = "certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Option(name = "--ca-cert", multiValued = true, description =
        "CA Certificate file")
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
            outKs.setKeyEntry(alias, inKs.getKey(alias, pwd), pwd,
                inKs.getCertificateChain(alias));
          } else {
            outKs.setCertificateEntry(alias, inKs.getCertificate(alias));
          }
        }
      }

      try (OutputStream out =
               Files.newOutputStream(Paths.get(expandFilepath(p12File)))) {
        outKs.store(out, pwd);
        println("updated certificate");
        return null;
      }
    } // method execute0

    private void assertMatch(KeyStore ks, X509Cert cert, String password)
        throws Exception {
      KeySpec keySpec = KeySpec.ofPublicKey(cert.subjectPublicKeyInfo());
      if (keySpec.isMontgomeryEC() || keySpec.isMlkem() ||
          keySpec.isCompositeMLKEM()) {
        // cannot be checked via creating dummy signature, just compare the
        // public keys
        char[] pwd = password.toCharArray();
        KeypairWithCert kp = KeypairWithCert.fromKeystore(ks, null, pwd, null);
        byte[] expectedEncoded = kp.publicKey().getEncoded();
        byte[] encoded = cert.publicKey().getEncoded();
        if (!Arrays.equals(expectedEncoded, encoded)) {
          throw new XiSecurityException(
              "the certificate and private do not match");
        }
      } else {
        SignerConf conf = new SignerConf();
        conf.setKeystore("file:" + expandFilepath(p12File))
            .setParallelism(1);
        if (password != null) {
          conf.setPassword(password);
        }

        securityFactory.createSigner("PKCS12", conf, cert);
      }
    } // method assertMatch

  } // class UpdateCertP12

  @Command(scope = "xi", name = "keypair-p12", description =
      "generate keypair in PKCS#12 keystore")
  @Service
  public static class KeypairP12 extends P12KeyGenAction {

    @Option(name = "--keyspec", required = true, description = "key spec")
    @Completion(SecurityCompleters.KeySpecCompleter.class)
    private String keyspecStr;

    @Option(name = "--unsigned", description =
        "whether to use empty signature in the certificate stored in keystore")
    @Completion(SecurityCompleters.KeySpecCompleter.class)
    private Boolean unsigned;

    @Override
    protected Object execute0() throws Exception {
      KeySpec keySpec = KeySpec.ofKeySpec(keyspecStr);
      KeystoreGenerationParameters keyGenParams = getKeyGenParameters();
      if (unsigned != null) {
        keyGenParams.setUnsigned(unsigned);
      }
      KeyStoreWrapper keypair = KeyUtil.generateKeypair3(keySpec, keyGenParams);
      saveKey(keypair);
      return null;
    }

  } // class EcP12

  public abstract static class P12KeyGenAction extends SecurityAction {

    @Option(name = "--out", aliases = "-o", required = true, description =
        "where to save the key")
    @Completion(FileCompleter.class)
    protected String keyOutFile;

    @Option(name = "--password", description =
        "password of the keystore file, as plaintext or PBE-encrypted.")
    protected String passwordHint;

    protected void saveKey(KeyStoreWrapper keyGenerationResult)
        throws IOException {
      saveVerbose("saved PKCS#12 keystore to file", keyOutFile,
          Args.notNull(keyGenerationResult, "keyGenerationResult").keystore());
    }

    protected KeystoreGenerationParameters getKeyGenParameters()
      throws IOException, PasswordResolverException {
      KeystoreGenerationParameters params =
          new KeystoreGenerationParameters(getPassword());

      SecureRandom random = securityFactory.random4Key();
      if (random != null) {
        params.setRandom(random);
      }

      return params;
    }

    private char[] getPassword()
        throws IOException, PasswordResolverException {
      char[] pwdInChar = readPasswordIfNotSet("Enter the keystore password",
          passwordHint);
      if (pwdInChar != null) {
        passwordHint = new String(pwdInChar);
      }
      return pwdInChar;
    }

  } // class P12KeyGenAction

  public abstract static class P12SecurityAction extends SecurityAction {

    @Option(name = "--p12", required = true, description =
        "PKCS#12 keystore file")
    @Completion(FileCompleter.class)
    protected String p12File;

    @Option(name = "--password", description =
        "password of the PKCS#12 file, as plaintext or PBE-encrypted.")
    protected String passwordHint;

    protected char[] getPassword()
        throws IOException, PasswordResolverException {
      char[] pwdInChar = readPasswordIfNotSet("Enter the keystore password",
          passwordHint);
      if (pwdInChar != null) {
        passwordHint = new String(pwdInChar);
      }
      return pwdInChar;
    }

    protected KeyStore getInKeyStore()
        throws IOException, NoSuchAlgorithmException, CertificateException,
        KeyStoreException, PasswordResolverException {
      try (InputStream in =
               Files.newInputStream(Paths.get(expandFilepath(p12File)))) {
        KeyStore ks = KeyUtil.getInKeyStore("PKCS12");
        ks.load(in, getPassword());
        return ks;
      }
    }

  } // class P12SecurityAction

  @Command(scope = "xi", name = "pkcs12", description =
      "export PKCS#12 key store, like the 'openssl pkcs12' command")
  @Service
  public static class Pkcs12 extends P12SecurityAction {

    @Option(name = "--key-out", required = true, description =
        "where to save the key")
    @Completion(FileCompleter.class)
    private String keyOutFile;

    @Option(name = "--cert-out", required = true, description =
        "where to save the certificate")
    @Completion(FileCompleter.class)
    private String certOutFile;

    @Override
    protected Object execute0() throws Exception {
      char[] password = getPassword();
      try (InputStream keystoreStream =
               Files.newInputStream(Paths.get(expandFilepath(p12File)))) {
        KeypairWithCert kp = KeypairWithCert.fromKeystore("PKCS12",
            keystoreStream, password, null, password, (X509Cert) null);
        byte[] encodedKey = PemEncoder.encode(
            kp.getKey().getEncoded(), PemLabel.PRIVATE_KEY);
        byte[] encodedCert = PemEncoder.encode(
            kp.x509CertChain()[0].getEncoded(), PemLabel.CERTIFICATE);

        IoUtil.save(keyOutFile, encodedKey);
        IoUtil.save(certOutFile, encodedCert);
      }
      return null;
    }

  } // class Pkcs12

}
