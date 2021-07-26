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

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.security.*;
import org.xipki.security.pkcs12.KeypairWithCert;
import org.xipki.security.pkcs12.KeystoreGenerationParameters;
import org.xipki.security.pkcs12.P12KeyGenerationResult;
import org.xipki.security.pkcs12.P12KeyGenerator;
import org.xipki.security.shell.Actions.CsrGenAction;
import org.xipki.security.shell.Actions.SecurityAction;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.*;
import org.xipki.util.PemEncoder.PemLabel;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
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
 * @author Lijun Liao
 */

public class P12Actions {

  @Command(scope = "xi", name = "secretkey-p12",
      description = "generate secret key in JCEKS (not PKCS#12) keystore")
  @Service
  public static class SecretkeyP12 extends P12KeyGenAction {

    @Option(name = "--key-type", required = true,
        description = "keytype, current only AES, DES3 and GENERIC are supported")
    @Completion(SecurityCompleters.SecretKeyTypeCompleter.class)
     private String keyType;

    @Option(name = "--key-size", required = true, description = "keysize in bit")
    private Integer keysize;

    @Override
    protected Object execute0()
        throws Exception {
      if (!("AES".equalsIgnoreCase(keyType) || "DES3".equalsIgnoreCase(keyType)
            || "GENERIC".equalsIgnoreCase(keyType))) {
        throw new IllegalCmdParamException("invalid keyType " + keyType);
      }

      P12KeyGenerationResult key = new P12KeyGenerator().generateSecretKey(
          keyType.toUpperCase(), keysize, getKeyGenParameters());
      saveKey(key);

      return null;
    }

  } // class SecretkeyP12

  @Command(scope = "xi", name = "export-cert-p12",
      description = "export certificate from PKCS#12 keystore")
  @Service
  public static class ExportCertP12 extends P12SecurityAction {

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outFile;

    @Override
    protected Object execute0()
        throws Exception {
      KeyStore ks = getKeyStore();

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

  @Command(scope = "xi", name = "update-cert-p12",
      description = "update certificate in PKCS#12 keystore")
  @Service
  public static class UpdateCertP12 extends P12SecurityAction {

    @Option(name = "--cert", required = true, description = "certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Option(name = "--ca-cert", multiValued = true, description = "CA Certificate file")
    @Completion(FileCompleter.class)
    private Set<String> caCertFiles;

    @Override
    protected Object execute0()
        throws Exception {
      KeyStore ks = getKeyStore();

      char[] pwd = getPassword();
      X509Cert newCert = X509Util.parseCert(new File(certFile));

      assertMatch(ks, newCert, new String(pwd));

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
        throw new XiSecurityException("could not find private key");
      }

      Key key = ks.getKey(keyname, pwd);
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

      ks.setKeyEntry(keyname, key, pwd, jceCertChain);

      try (OutputStream out = Files.newOutputStream(Paths.get(p12File))) {
        ks.store(out, pwd);
        println("updated certificate");
        return null;
      }
    } // method execute0

    private void assertMatch(KeyStore ks, X509Cert cert, String password)
        throws Exception {
      String keyAlgName = cert.getPublicKey().getAlgorithm();
      if (EdECConstants.X25519.equalsIgnoreCase(keyAlgName)
          || EdECConstants.X448.equalsIgnoreCase(keyAlgName)) {
        // cannot be checked via creating dummy signature, just compare the public keys
        char[] pwd = password.toCharArray();
        KeypairWithCert kp = KeypairWithCert.fromKeystore(ks, null, pwd, (X509Cert[]) null);
        byte[] expectedEncoded = kp.getPublicKey().getEncoded();
        byte[] encoded = cert.getPublicKey().getEncoded();
        if (!Arrays.equals(expectedEncoded, encoded)) {
          throw new XiSecurityException("the certificate and private do not match");
        }
      } else {
        ConfPairs pairs = new ConfPairs("keystore", "file:" + p12File);
        if (password != null) {
          pairs.putPair("password", new String(password));
        }

        HashAlgo hashAlgo = HashAlgo.SHA256;
        SignatureAlgoControl algoControl = null;
        AlgorithmIdentifier algId = cert.getSubjectPublicKeyInfo().getAlgorithm();
        if (X9ObjectIdentifiers.id_ecPublicKey.equals(algId.getAlgorithm())) {
          if (ASN1ObjectIdentifier.getInstance(algId.getParameters())
                  .equals(GMObjectIdentifiers.sm2p256v1)) {
            hashAlgo = HashAlgo.SM3;
            algoControl = new SignatureAlgoControl(false, false, true);
          }
        }
        SignerConf conf = new SignerConf(pairs.getEncoded(), hashAlgo, algoControl);
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

    @Option(name = "--password", description = "password of the PKCS#12 keystore file")
    private String password;

    private char[] getPassword()
        throws IOException {
      char[] pwdInChar = readPasswordIfNotSet(password);
      if (pwdInChar != null) {
        password = new String(pwdInChar);
      }
      return pwdInChar;
    }

    public KeyStore getKeyStore()
        throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
      KeyStore ks;
      try (InputStream in = Files.newInputStream(Paths.get(expandFilepath(p12File)))) {
        ks = KeyUtil.getKeyStore("PKCS12");
        ks.load(in, getPassword());
      }
      return ks;
    }

    @Override
    protected ConcurrentContentSigner getSigner()
        throws ObjectCreationException {
      SignatureAlgoControl signatureAlgoControl = getSignatureAlgoControl();
      char[] pwd;
      try {
        pwd = getPassword();
      } catch (IOException ex) {
        throw new ObjectCreationException("could not read password: " + ex.getMessage(), ex);
      }

      ConfPairs conf = new ConfPairs("password", new String(pwd));
      conf.putPair("parallelism", Integer.toString(1));
      conf.putPair("keystore", "file:" + p12File);

      HashAlgo ha;
      try {
        ha = HashAlgo.getInstance(hashAlgo);
      } catch (NoSuchAlgorithmException ex) {
        throw new ObjectCreationException(ex.getMessage());
      }

      SignerConf signerConf = new SignerConf(conf.getEncoded(), ha, signatureAlgoControl);
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

    @Option(name = "--subject", aliases = "-s",
        description = "subject of the self-signed certificate")
    private String subject;

    @Option(name = "--plen", description = "bit length of the prime")
    private Integer plen = 2048;

    @Option(name = "--qlen", description = "bit length of the sub-prime")
    private Integer qlen;

    @Override
    protected Object execute0()
        throws Exception {
      if (plen % 1024 != 0) {
        throw new IllegalCmdParamException("plen is not multiple of 1024: " + plen);
      }

      if (qlen == null) {
        if (plen <= 1024) {
          qlen = 160;
        } else if (plen <= 2048) {
          qlen = 224;
        } else {
          qlen = 256;
        }
      }

      P12KeyGenerationResult keypair = new P12KeyGenerator().generateDSAKeypair(plen,
          qlen, getKeyGenParameters(), subject);
      saveKey(keypair);

      return null;
    } // method execute0

  } // class DsaP12

  @Command(scope = "xi", name = "ec-p12", description = "generate EC keypair in PKCS#12 keystore")
  @Service
  public static class EcP12 extends P12KeyGenAction {

    @Option(name = "--subject", aliases = "-s",
        description = "subject of the self-signed certificate")
    protected String subject;

    @Option(name = "--curve", description = "EC curve name or OID")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName = "secp256r1";

    @Override
    protected Object execute0()
        throws Exception {
      P12KeyGenerator keyGen = new P12KeyGenerator();
      KeystoreGenerationParameters keyGenParams = getKeyGenParameters();
      P12KeyGenerationResult keypair;

      ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(curveName);
      if (curveOid != null) {
        keypair = keyGen.generateEdECKeypair(curveOid, keyGenParams, subject);
      } else {
        curveOid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName);
        keypair = new P12KeyGenerator().generateECKeypair(curveOid, keyGenParams, subject);
      }
      saveKey(keypair);

      return null;
    }

  } // class EcP12

  public abstract static class P12KeyGenAction extends SecurityAction {

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the key")
    @Completion(FileCompleter.class)
    protected String keyOutFile;

    @Option(name = "--password", description = "password of the keystore file")
    protected String password;

    protected void saveKey(P12KeyGenerationResult keyGenerationResult)
        throws IOException {
      Args.notNull(keyGenerationResult, "keyGenerationResult");
      saveVerbose("saved PKCS#12 keystore to file", keyOutFile, keyGenerationResult.keystore());
    }

    protected KeystoreGenerationParameters getKeyGenParameters()
        throws IOException {
      KeystoreGenerationParameters params = new KeystoreGenerationParameters(getPassword());

      SecureRandom random = securityFactory.getRandom4Key();
      if (random != null) {
        params.setRandom(random);
      }

      return params;
    }

    private char[] getPassword()
        throws IOException {
      char[] pwdInChar = readPasswordIfNotSet(password);
      if (pwdInChar != null) {
        password = new String(pwdInChar);
      }
      return pwdInChar;
    }

  } // class P12KeyGenAction

  @Command(scope = "xi", name = "rsa-p12", description = "generate RSA keypair in PKCS#12 keystore")
  @Service
  public static class RsaP12 extends P12KeyGenAction {

    @Option(name = "--subject", aliases = "-s",
        description = "subject of the self-signed certificate")
    private String subject;

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize = 2048;

    @Option(name = "-e", description = "public exponent")
    private String publicExponent = "0x10001";

    @Override
    protected Object execute0()
        throws Exception {
      if (keysize % 1024 != 0) {
        throw new IllegalCmdParamException("keysize is not multiple of 1024: " + keysize);
      }

      P12KeyGenerationResult keypair = new P12KeyGenerator().generateRSAKeypair(keysize,
          toBigInt(publicExponent), getKeyGenParameters(), subject);
      saveKey(keypair);

      return null;
    }

  } // class RsaP12

  public abstract static class P12SecurityAction extends SecurityAction {

    @Option(name = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FileCompleter.class)
    protected String p12File;

    @Option(name = "--password", description = "password of the PKCS#12 file")
    protected String password;

    protected char[] getPassword()
        throws IOException {
      char[] pwdInChar = readPasswordIfNotSet(password);
      if (pwdInChar != null) {
        password = new String(pwdInChar);
      }
      return pwdInChar;
    }

    protected KeyStore getKeyStore()
        throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException,
          NoSuchProviderException {
      KeyStore ks;
      try (InputStream in = Files.newInputStream(Paths.get(expandFilepath(p12File)))) {
        ks = KeyUtil.getKeyStore("PKCS12");
        ks.load(in, getPassword());
      }
      return ks;
    }

  } // class P12SecurityAction

  @Command(scope = "xi", name = "sm2-p12",
      description = "generate SM2 (curve sm2p256v1) keypair in PKCS#12 keystore")
  @Service
  public static class Sm2P12 extends P12KeyGenAction {

    @Option(name = "--subject", aliases = "-s",
        description = "subject of the self-signed certificate")
    protected String subject;

    @Override
    protected Object execute0()
        throws Exception {
      P12KeyGenerationResult keypair = new P12KeyGenerator().generateECKeypair(
          GMObjectIdentifiers.sm2p256v1, getKeyGenParameters(), subject);
      saveKey(keypair);

      return null;
    }

  } // class Sm2P12

  @Command(scope = "xi", name = "pkcs12",
      description = "export PKCS#12 key store, like the 'openssl pkcs12' command")
  @Service
  public static class Pkcs12 extends P12SecurityAction {

    @Option(name = "--key-out", required = true, description = "where to save the key")
    @Completion(FileCompleter.class)
    private String keyOutFile;

    @Option(name = "--cert-out", required = true, description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String certOutFile;

    @Override
    protected Object execute0()
        throws Exception {
      char[] password = getPassword();
      try (InputStream keystoreStream = new FileInputStream(p12File)) {
        KeypairWithCert kp = KeypairWithCert.fromKeystore("PKCS12",
                              keystoreStream, password, null, password, (X509Cert) null);
        byte[] encodedKey = PemEncoder.encode(kp.getKey().getEncoded(), PemLabel.PRIVATE_KEY);
        byte[] encodedCert = PemEncoder.encode(kp.getCertificateChain()[0].getEncoded(),
                              PemLabel.CERTIFICATE);
        IoUtil.save(keyOutFile, encodedKey);
        IoUtil.save(certOutFile, encodedCert);
      }
      return null;
    }

  } // class Pkcs12

}
