// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.SecurityFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.codec.Base64;
import org.xipki.util.codec.Hex;
import org.xipki.util.extra.misc.CompareUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.extra.misc.PemEncoder;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Security actions.
 *
 * @author Lijun Liao (xipki)
 */

public class SecurityActions {

  @Command(scope = "xi", name = "cert-info", description =
      "print certificate information")
  @Service
  public static class CertInfo extends SecurityAction {

    @Option(name = "--in", description = "certificate file")
    @Completion(FileCompleter.class)
    private String inFile;

    @Option(name = "--hex", aliases = "-h", description =
        "print (serial) number in hex format")
    private Boolean hex = Boolean.FALSE;

    @Option(name = "--der", description =
        "print DER-encoded issuer and subject in hex format")
    private Boolean der = Boolean.FALSE;

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

    @Option(name = "--text", description = "print text (as openssl x509 -text)")
    private Boolean text;

    @Option(name = "--hash", description = "hash algorithm name")
    @Completion(Completers.HashAlgCompleter.class)
    protected String hashAlgo = "SHA256";

    @Override
    protected Object execute0() throws Exception {
      X509Cert cert = X509Util.parseCert(IoUtil.read(inFile));

      if (text != null && text) {
        return cert.toString();
      } else if (serial != null && serial) {
        return getNumber(cert.serialNumber());
      } else if (subject != null && subject) {
        return (der != null && der)
            ? Hex.encode(cert.subject().getEncoded())
            : cert.subject().toString();
      } else if (issuer != null && issuer) {
        return (der != null && der)
            ? Hex.encode(cert.issuer().getEncoded())
            : cert.issuer().toString();
      } else if (notBefore != null && notBefore) {
        return toUtcTimeyyyyMMddhhmmssZ(cert.notBefore());
      } else if (notAfter != null && notAfter) {
        return toUtcTimeyyyyMMddhhmmssZ(cert.notAfter());
      } else if (fingerprint != null && fingerprint) {
        byte[] encoded = cert.getEncoded();
        return HashAlgo.getInstance(hashAlgo).hexHash(encoded);
      } else {
        return null;
      }
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

  @Command(scope = "xi", name = "convert-keystore", description =
      "Convert keystore")
  @Service
  public static class ConvertKeystore extends SecurityAction {

    @Option(name = "--in", required = true, description =
        "source keystore file")
    @Completion(FileCompleter.class)
    private String inFile;

    @Option(name = "--intype", required = true, description =
        "type of the source keystore")
    @Completion(SecurityCompleters.KeystoreTypeCompleter.class)
    private String inType;

    @Option(name = "--inpwd", description =
        "password of the source keystore, as plaintext or PBE-encrypted.")
    private String inPwdHint;

    @Option(name = "--out", required = true, description =
        "destination keystore file")
    @Completion(FileCompleter.class)
    private String outFile;

    @Option(name = "--outtype", required = true, description =
        "type of the destination keystore")
    @Completion(SecurityCompleters.KeystoreTypeWithPEMCompleter.class)
    private String outType;

    @Option(name = "--outpwd", description =
        "password of the destination keystore, as plaintext or " +
            "PBE-encrypted.\n" +
        "For PEM, you may use NONE to save the private key unprotected.")
    private String outPwdHint;

    private static final byte[] CRLF = new byte[]{'\r', '\n'};

    @Override
    protected Object execute0() throws Exception {
      File realInFile = new File(IoUtil.expandFilepath(inFile));
      File realOutFile = new File(IoUtil.expandFilepath(outFile));

      if (CompareUtil.equals(realInFile, realOutFile)) {
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

      byte[] outBytes;
      try {
        char[] inPassword = readPasswordIfNotSet(
            "password of the source keystore", inPwdHint);
        try (InputStream inStream = Files.newInputStream(realInFile.toPath())) {
          inKs.load(inStream, inPassword);
        }

        boolean needsPassword = !("PEM".equalsIgnoreCase(outType)
            && "NONE".equalsIgnoreCase(outPwdHint));
        char[] outPassword = needsPassword
             ? readPasswordIfNotSet(
                "password of the destination keystore", outPwdHint)
            : null;

        OutputEncryptor pemOe = null;
        if ("PEM".equalsIgnoreCase(outType) && outPassword != null) {
          JceOpenSSLPKCS8EncryptorBuilder eb =
              new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES);
          eb.setPassword(outPassword);
          pemOe = eb.build();
        }

        Enumeration<String> aliases = inKs.aliases();
        while (aliases.hasMoreElements()) {
          String alias = aliases.nextElement();
          if (inKs.isKeyEntry(alias)) {
            java.security.cert.Certificate[] certs =
                inKs.getCertificateChain(alias);
            Key key = inKs.getKey(alias, inPassword);
            if (outKs != null) {
              outKs.setKeyEntry(alias, key, outPassword, certs);
            } else {
              if (outPassword == null) {
                outPemKs.write(PemEncoder.encode(key.getEncoded(),
                    PemEncoder.PemLabel.PRIVATE_KEY));
              } else {
                JcaPKCS8Generator gen =
                    new JcaPKCS8Generator((PrivateKey) key, pemOe);
                PemObject po = gen.generate();
                outPemKs.write(PemEncoder.encode(po.getContent(),
                    PemEncoder.PemLabel.ENCRYPTED_PRIVATE_KEY));
              }

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

        if (outPemKs == null) {
          try (ByteArrayOutputStream bout = new ByteArrayOutputStream(4096)) {
            outKs.store(bout, outPassword);
            outBytes = bout.toByteArray();
          }
        } else {
          outBytes = outPemKs.toByteArray();
        }
      } finally {
        if (outPemKs != null) {
          outPemKs.close();
        }
      }

      saveVerbose("saved destination keystore to file",
          realOutFile, outBytes);
      return null;
    }

    private static void writePemCert(
        OutputStream out, java.security.cert.Certificate cert)
        throws CertificateEncodingException, IOException {
      out.write(PemEncoder.encode(cert.getEncoded(),
          PemEncoder.PemLabel.CERTIFICATE));
    }

  } // class ConvertKeystore

  @Command(scope = "xi", name = "crl-info", description =
      "print CRL information")
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
        ASN1Encodable asn1 = crl.getTBSCertList().getExtensions()
                              .getExtensionParsedValue(OIDs.Extn.cRLNumber);
        if (asn1 == null) {
          return "null";
        }
        return getNumber(ASN1Integer.getInstance(asn1).getPositiveValue());
      } else if (issuer != null && issuer) {
        return crl.getIssuer().toString();
      } else if (thisUpdate != null && thisUpdate) {
        return toUtcTimeyyyyMMddhhmmssZ(
            crl.getThisUpdate().getDate().toInstant());
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

  @Command(scope = "xi", name = "import-cert", description =
      "import certificates to a keystore")
  @Service
  public static class ImportCert extends SecurityAction {

    @Option(name = "--keystore", required = true, description = "keystore file")
    @Completion(FileCompleter.class)
    private String ksFile;

    @Option(name = "--type", required = true, description =
        "type of the keystore")
    @Completion(SecurityCompleters.KeystoreTypeCompleter.class)
    private String ksType;

    @Option(name = "--password", description =
        "password of the keystore, as plaintext or PBE-encrypted.")
    private String ksPwdHint;

    @Option(name = "--cert", aliases = "-c", required = true,
        multiValued = true, description = "certificate files")
    @Completion(FileCompleter.class)
    private List<String> certFiles;

    @Override
    protected Object execute0() throws Exception {
      File realKsFile = new File(IoUtil.expandFilepath(ksFile));
      KeyStore ks = KeyUtil.getOutKeyStore(ksType);
      char[] password = readPasswordIfNotSet(
          "Enter the keystore password", ksPwdHint);

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
        String baseAlias = X509Util.getCommonName(cert.subject());
        String alias = baseAlias;
        int idx = 2;
        while (aliases.contains(alias)) {
          alias = baseAlias + "-" + (idx++);
        }
        ks.setCertificateEntry(alias, cert.toJceCert());
        aliases.add(alias);
      }

      try (ByteArrayOutputStream bout = new ByteArrayOutputStream(4096)) {
        ks.store(bout, password);
        saveVerbose("saved keystore to file",
            realKsFile, bout.toByteArray());
      }
      return null;
    }

  } // class ImportCert

  @Command(scope = "xi", name = "export-cert-p7m", description =
      "export (the first) certificate from CMS signed data")
  @Service
  public static class ExportCertP7m extends SecurityAction {

    @Option(name = "--outform", description =
        "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Argument(index = 0, name = "p7m file", required = true, description =
        "File of the CMS signed data")
    @Completion(FileCompleter.class)
    private String p7mFile;

    @Argument(index = 1, name = "cert file", required = true, description =
        "File to save the certificate")
    @Completion(FileCompleter.class)
    private String certFile;

    @Override
    protected Object execute0() throws Exception {
      byte[] encodedCert = extractCertFromSignedData(IoUtil.read(p7mFile));
      saveVerbose("saved certificate to file", certFile,
          encodeCert(encodedCert, outform));
      return null;
    }

  } // class ExportCertP7m

  @Command(scope = "xi", name = "export-keycert-pem", description =
      "export key and certificate from the PEM file")
  @Service
  public static class ExportKeyCertPem extends SecurityAction {

    @Option(name = "--outform", description =
        "output format of the key and certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Argument(index = 0, name = "PEM-file", required = true,
        description = "PEM file containing the key and certificate")
    @Completion(FileCompleter.class)
    private String pemFile;

    @Argument(index = 1, name = "key-file", required = true, description =
        "File to save the private key")
    @Completion(FileCompleter.class)
    private String keyFile;

    @Argument(index = 2, name = "cert-file", required = true, description =
        "File to save the certificate")
    @Completion(FileCompleter.class)
    private String certFile;

    @Override
    protected Object execute0() throws Exception {
      byte[] keyBytes = null;
      byte[] certBytes = null;

      try (PemReader reader = new PemReader(new FileReader(
          IoUtil.expandFilepath(pemFile)))) {
        PemObject pemObject;
        while ((pemObject = reader.readPemObject()) != null) {
          String type = pemObject.getType();
          if ("PRIVATE KEY".equals(type)) {
            if (keyBytes == null) {
              keyBytes = pemObject.getContent();
            }
          } else if ("CERTIFICATE".equals(type)) {
            if (certBytes == null) {
              certBytes = pemObject.getContent();
            }
          }

          if (keyBytes != null && certBytes != null) {
            break;
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

        saveVerbose("certificate saved to file", certFile,
            encodeCert(certBytes, outform));
      }
      return null;
    }

  } // class ExportKeyCertPem

  @Command(scope = "xi", name = "export-keycert-est", description =
      "export key and certificate from the response of EST's serverkeygen")
  @Service
  public static class ExportKeyCertEst extends SecurityAction {

    @Option(name = "--outform", description =
        "output format of the key and certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Argument(index = 0, name = "response-file", required = true, description =
        "File containing the response")
    @Completion(FileCompleter.class)
    private String estRespFile;

    @Argument(index = 1, name = "key-file", required = true, description =
        "File to save the private key")
    @Completion(FileCompleter.class)
    private String keyFile;

    @Argument(index = 2, name = "cert-file", required = true, description =
        "File to save the certificate")
    @Completion(FileCompleter.class)
    private String certFile;

    @Override
    protected Object execute0() throws Exception {
      try (BufferedReader reader = new BufferedReader(new FileReader(
          IoUtil.expandFilepath(estRespFile)))) {
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
        saveVerbose("certificate saved to file", certFile,
            encodeCert(rawCertBytes, outform));
      }
      return null;
    }

    private static Object[] readBlock(BufferedReader reader, String boundary)
        throws IOException {
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
          } else if (StringUtil.startsWithIgnoreCase(line,
              "content-transfer-encoding:")) {
            encoding = line.substring("content-transfer-encoding:".length())
                        .trim();
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

    protected SecretKey readSecretKeyFromKeystore(
        String ksFile, String alias, String passwordHint)
        throws CmdFailure {
      try {
        KeyStore ks = KeyUtil.getInKeyStore("JCEKS");
        char[] password = readPasswordIfNotSet(
            "password of the keystore " + ksFile, passwordHint);

        SecretKey key = null;
        File file = IoUtil.expandFilepath(new File(ksFile));
        try (InputStream is = Files.newInputStream(file.toPath())) {
          ks.load(is, password);
          if (ks.isKeyEntry(alias)) {
            key = (SecretKey) ks.getKey(alias, password);
          }
        }

        if (key == null) {
          throw new CmdFailure(ksFile + " does not contain any secret key");
        }
        return key;
      } catch (GeneralSecurityException | IOException | RuntimeException ex) {
        throw new CmdFailure("error reading secret key from " + ksFile, ex);
      }
    }

  } // class SecurityAction

  private static byte[] extractCertFromSignedData(byte[] cmsBytes)
      throws CmdFailure, IOException {
    ContentInfo ci = ContentInfo.getInstance(X509Util.toDerEncoded(cmsBytes));
    ASN1Set certs = SignedData.getInstance(ci.getContent()).getCertificates();
    if (certs == null || certs.size() == 0) {
      throw new CmdFailure("Found no certificate");
    }

    return certs.getObjectAt(0).toASN1Primitive().getEncoded();
  }

}
