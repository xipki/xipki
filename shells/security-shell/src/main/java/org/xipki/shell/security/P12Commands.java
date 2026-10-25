// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.security;

import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.codec.util.Args;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.pkcs12.KeyStoreWrapper;
import org.xipki.pkix.pkcs12.KeypairWithCert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.Pkcs12KeyStoreWrapper;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.xi.Completers;
import org.xipki.pkix.util.misc.PemEncoder;
import org.xipki.codec.util.IoUtil;
import org.xipki.pkix.util.password.PasswordResolverException;
import org.xipki.shell.xi.XiShellBaseCommand;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Actions for PKCS#12 security.
 *
 * @author Lijun Liao (xipki)
 */
public class P12Commands {
  @Command(name = "secretkey-p12", description = "generate secret key in JCEKS keystore",
      mixinStandardHelpOptions = true)
  static class SecretkeyP12Command extends XiShellBaseCommand {

    @Option(names = "--key-type", required = true, description = "keytype, e.g. AES, DES3, SM4")
    @Completion(SecurityCompleters.SecretKeyTypeCompleter.class)
    private String keyType;

    @Option(names = "--key-size", description = "keysize in bit")
    private Integer keysize;

    @Option(names = {"--out", "-o"}, required = true, description = "where to save the key")
    @Completion(FilePathCompleter.class)
    private String keyOutFile;

    @Option(names = "--password", interactive = true, description = "password of the keystore file")
    private String passwordHint;

    @Override
    public void run() {
      try {
        if (keysize == null) {
          if ("DES3".equalsIgnoreCase(keyType)) {
            keysize = 192;
          } else if ("SM4".equalsIgnoreCase(keyType)) {
            keysize = 128;
          } else {
            throw new IllegalArgumentException("key-size is not specified");
          }
        }

        KeyStoreWrapper key = KeyUtil.generateSecretKey(
            keyType.toUpperCase(), keysize, getKeyGenParameters(passwordHint, null));
        saveVerbose("saved keystore to file", keyOutFile,
            Args.notNull(key, "key").keystore());
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "export-cert-p12", description = "export certificate from PKCS#12 keystore",
      mixinStandardHelpOptions = true)
  static class ExportCertP12Command extends XiShellBaseCommand {

    @Option(names = "--outform", description = "output format of the certificate")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FilePathCompleter.class)
    private String p12File;

    @Option(names = "--password", description = "password of the PKCS#12 file")
    private String passwordHint;

    @Option(names = {"--out", "-o"}, required = true, description = "where to save the certificate")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    public void run() {
      try {
        Pkcs12KeyStore ks = getInKeyStore(p12File, passwordHint);
        String keyname = null;
        Set<String> aliases = ks.aliases();
        for (String alias : aliases) {
          if (ks.isKeyEntry(alias)) {
            keyname = alias;
            break;
          }
        }

        if (keyname == null) {
          throw new IOException("could not find private key");
        }

        Certificate cert = ks.getCertificate(keyname);
        saveVerbose("saved certificate to file", outFile,
            encodeCert(cert.getEncoded(), outform));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "update-cert-p12",
      description = "update certificate in PKCS#12 keystore", mixinStandardHelpOptions = true)
  static class UpdateCertP12Command extends XiShellBaseCommand {

    @Option(names = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FilePathCompleter.class)
    private String p12File;

    @Option(names = "--password", description = "password of the PKCS#12 file")
    private String passwordHint;

    @Option(names = "--cert", required = true, description = "certificate file")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(names = "--ca-cert", split = ",", description = "CA certificate files")
    @Completion(FilePathCompleter.class)
    private Set<String> caCertFiles;

    @Override
    public void run() {
      try {
        Pkcs12KeyStore inKs = getInKeyStore(p12File, passwordHint);
        char[] pwd = SecurityCommands.resolveP12Password(passwordHint);
        X509Cert newCert = X509Util.parseCert(new File(certFile));
        assertMatch(inKs, newCert, pwd);

        String keyname = null;
        Set<String> aliases = inKs.aliases();
        for (String alias : aliases) {
          if (inKs.isKeyEntry(alias)) {
            keyname = alias;
            break;
          }
        }

        if (keyname == null) {
          throw new IOException("could not find private key");
        }

        PrivateKeyInfo key = inKs.getKey(keyname);
        Set<X509Cert> caCerts = new HashSet<>();
        if (caCertFiles != null) {
          for (String caCertFile : caCertFiles) {
            caCerts.add(X509Util.parseCert(new File(caCertFile)));
          }
        }
        X509Cert[] certChain = X509Util.buildCertPath(newCert, caCerts);
        List<Certificate> jceCertChain = new ArrayList<>(certChain.length);
        for (X509Cert x509Cert : certChain) {
          jceCertChain.add(x509Cert.getCert());
        }

        Pkcs12KeyStore outKs = KeyUtil.loadPKCS12KeyStore((byte[]) null, null);
        aliases = inKs.aliases();
        for (String alias : aliases) {
          if (alias.equalsIgnoreCase(keyname)) {
            outKs.setKeyEntry(keyname, key, jceCertChain);
          } else if (inKs.isKeyEntry(alias)) {
            outKs.setKeyEntry(alias, inKs.getKey(alias), inKs.getCertificateChain(alias));
          } else {
            outKs.setCertificateEntry(alias, inKs.getCertificate(alias));
          }
        }

        try (OutputStream out = Files.newOutputStream(Paths.get(IoUtil.expandFilepath(p12File)))) {
          outKs.store(out, pwd);
          println("updated certificate");
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private void assertMatch(Pkcs12KeyStore ks, X509Cert cert, char[] password) throws Exception {
      KeypairWithCert kp = KeypairWithCert.fromKeystore(ks, null, password, null);
      byte[] expectedEncoded = kp.publicKey().getEncoded();
      byte[] encoded = cert.publicKey().getEncoded();
      if (!Arrays.equals(expectedEncoded, encoded)) {
        throw new IOException("the certificate and private key do not match");
      }
    }
  }

  @Command(name = "keypair-p12", description = "generate keypair in PKCS#12 keystore",
      mixinStandardHelpOptions = true)
  static class KeypairP12Command extends XiShellBaseCommand {

    @Option(names = "--keyspec", required = true, description = "key spec")
    @Completion(SecurityCompleters.KeySpecCompleter.class)
    private String keyspecStr;

    @Option(names = "--unsigned", description = "whether to use empty signature in certificate")
    private Boolean unsigned;

    @Option(names = {"--out", "-o"}, required = true, description = "where to save the key")
    @Completion(FilePathCompleter.class)
    private String keyOutFile;

    @Option(names = "--password", description = "password of the keystore file")
    private String passwordHint;

    @Override
    public void run() {
      try {
        KeySpec keySpec = KeySpec.ofKeySpec(keyspecStr);
        KeystoreGenerationParameters keyGenParams = getKeyGenParameters(passwordHint, unsigned);
        Pkcs12KeyStoreWrapper keypair = KeyUtil.generateKeyPair3(keySpec, keyGenParams);
        saveVerbose("saved PKCS#12 keystore to file", keyOutFile,
            Args.notNull(keypair, "keypair").keystore());
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "pkcs12", description = "export PKCS#12 key store like openssl pkcs12",
      mixinStandardHelpOptions = true)
  static class Pkcs12Command extends XiShellBaseCommand {

    @Option(names = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FilePathCompleter.class)
    private String p12File;

    @Option(names = "--password", description = "password of the PKCS#12 file")
    private String passwordHint;

    @Option(names = "--key-out", required = true, description = "where to save the key")
    @Completion(FilePathCompleter.class)
    private String keyOutFile;

    @Option(names = "--cert-out", required = true, description = "where to save the certificate")
    @Completion(FilePathCompleter.class)
    private String certOutFile;

    @Override
    public void run() {
      try {
        char[] password = SecurityCommands.resolveP12Password(passwordHint);
        try (var keystoreStream = Files.newInputStream(Paths.get(IoUtil.expandFilepath(p12File)))) {
          KeypairWithCert kp = KeypairWithCert.fromPKCS12Keystore(
              keystoreStream, password, null, password, (X509Cert) null);
          byte[] encodedKey = PemEncoder.encode(kp.getKey().getEncoded(),
                                PemEncoder.PemLabel.PRIVATE_KEY);
          byte[] encodedCert = PemEncoder.encode(
              kp.x509CertChain()[0].getEncoded(), PemEncoder.PemLabel.CERTIFICATE);
          IoUtil.save(keyOutFile, encodedKey);
          IoUtil.save(certOutFile, encodedCert);
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  static Pkcs12KeyStore getInKeyStore(String p12File, String passwordHint)
      throws IOException, XiSecurityException, PasswordResolverException {
    try (InputStream in = Files.newInputStream(Paths.get(IoUtil.expandFilepath(p12File)))) {
      return KeyUtil.loadPKCS12KeyStore(in, SecurityCommands.resolveP12Password(passwordHint));
    }
  }

  static KeystoreGenerationParameters getKeyGenParameters(String passwordHint, Boolean unsigned)
      throws IOException, PasswordResolverException {
    char[] pwd = SecurityCommands.resolveP12Password(passwordHint);
    KeystoreGenerationParameters params = new KeystoreGenerationParameters(pwd);
    params.setRandom(new SecureRandom());
    if (unsigned != null) {
      params.setUnsigned(unsigned);
    }
    return params;
  }

}
