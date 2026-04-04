// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.security;

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
import org.xipki.security.Securities;
import org.xipki.security.pkcs12.PKCS12KeyStore;
import org.xipki.security.pkix.JceX509Certificate;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.xi.Completers;
import org.xipki.util.codec.Base64;
import org.xipki.util.codec.Hex;
import org.xipki.util.extra.misc.CompareUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.extra.misc.PemEncoder;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import org.xipki.util.password.PasswordResolverException;
import org.xipki.util.password.Passwords;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
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
 * The security shell.
 *
 * @author Lijun Liao (xipki)
 */
class SecurityCommands {

  @Command(name = "cert-info", description = "print certificate information",
      mixinStandardHelpOptions = true)
  static class CertInfoCommand extends ShellBaseCommand {

    @Option(names = "--in", description = "certificate file", required = true)
    @Completion(FilePathCompleter.class)
    private String inFile;

    @Option(names = "--hex", description = "print serial number in hex format")
    private boolean hex;

    @Option(names = "--der", description = "print DER-encoded issuer and subject in hex format")
    private boolean der;

    @Option(names = "--serial", description = "print serial number")
    private boolean serial;

    @Option(names = "--subject", description = "print subject")
    private boolean subject;

    @Option(names = "--issuer", description = "print issuer")
    private boolean issuer;

    @Option(names = "--not-before", description = "print notBefore")
    private boolean notBefore;

    @Option(names = "--not-after", description = "print notAfter")
    private boolean notAfter;

    @Option(names = "--fingerprint", description = "print fingerprint in hex")
    private boolean fingerprint;

    @Option(names = "--text", description = "print text")
    private boolean text;

    @Option(names = "--hash", description = "hash algorithm name")
    @Completion(Completers.HashAlgoCompleter.class)
    private String hashAlgo = "SHA256";

    @Override
    public void run() {
      try {
        X509Cert cert = X509Util.parseCert(IoUtil.read(inFile));
        String result;
        if (text) {
          result = cert.toString();
        } else if (serial) {
          result = getNumber(cert.serialNumber());
        } else if (subject) {
          result = der ? Hex.encode(cert.subject().getEncoded()) : cert.subject().toString();
        } else if (issuer) {
          result = der ? Hex.encode(cert.issuer().getEncoded()) : cert.issuer().toString();
        } else if (notBefore) {
          result = toUtcTime(cert.notBefore());
        } else if (notAfter) {
          result = toUtcTime(cert.notAfter());
        } else if (fingerprint) {
          result = HashAlgo.getInstance(hashAlgo).hexHash(cert.getEncoded());
        } else {
          result = cert.toString();
        }
        println(result);
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private String toUtcTime(Instant instant) {
      return DateUtil.toUtcTimeyyyyMMddhhmmss(instant) + "Z";
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
  }

  @Command(name = "convert-keystore", description = "Convert keystore",
      mixinStandardHelpOptions = true)
  static class ConvertKeystoreCommand extends ShellBaseCommand {

    @Option(names = "--in", required = true, description = "source keystore file")
    @Completion(FilePathCompleter.class)
    private String inFile;

    @Option(names = "--intype", required = true, description = "type of the source keystore")
    @Completion(SecurityCompleters.KeystoreTypeWithPEMCompleter.class)
    private String inType;

    @Option(names = "--inpwd", description = "password of the source keystore")
    private String inPwdHint;

    @Option(names = "--out", required = true, description = "destination keystore file")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Option(names = "--outtype", required = true, description = "type of the destination keystore")
    @Completion(SecurityCompleters.KeystoreTypeWithPEMCompleter.class)
    private String outType;

    @Option(names = "--outpwd", description = "password of the destination keystore")
    private String outPwdHint;

    @Override
    public void run() {
      try {
        File realInFile = new File(IoUtil.expandFilepath(inFile));
        File realOutFile = new File(IoUtil.expandFilepath(outFile));

        if (CompareUtil.equals(realInFile, realOutFile)) {
          throw new IllegalArgumentException("in and out cannot be the same");
        }

        KeyStore inKs = KeyStore.getInstance(inType);
        KeyStore outKs;
        ByteArrayOutputStream outPemKs;

        if ("PEM".equalsIgnoreCase(outType)) {
          outPemKs = new ByteArrayOutputStream();
          outKs = null;
        } else {
          outPemKs = null;
          outKs = KeyUtil.loadKeyStore(outType, null, null);
          outKs.load(null);
        }

        byte[] outBytes;
        try {
          char[] inPassword = readPasswordIfNotSet("password of the source keystore", inPwdHint);
          try (var inStream = Files.newInputStream(realInFile.toPath())) {
            inKs.load(inStream, inPassword);
          }

          boolean needsPassword = !("PEM".equalsIgnoreCase(outType)
              && "NONE".equalsIgnoreCase(outPwdHint));
          char[] outPassword = needsPassword
              ? readPasswordIfNotSet("password of the destination keystore", outPwdHint)
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
              java.security.cert.Certificate[] certs = inKs.getCertificateChain(alias);
              Key key = inKs.getKey(alias, inPassword);
              if (outKs != null) {
                outKs.setKeyEntry(alias, key, outPassword, certs);
              } else {
                if (outPassword == null) {
                  outPemKs.write(PemEncoder.encode(key.getEncoded(),
                                  PemEncoder.PemLabel.PRIVATE_KEY));
                } else {
                  JcaPKCS8Generator gen = new JcaPKCS8Generator((PrivateKey) key, pemOe);
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

        saveVerbose("saved destination keystore to file", realOutFile.toPath(), outBytes);
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private static void writePemCert(OutputStream out, java.security.cert.Certificate cert)
        throws CertificateEncodingException, IOException {
      out.write(PemEncoder.encode(cert.getEncoded(), PemEncoder.PemLabel.CERTIFICATE));
    }
  }

  @Command(name = "import-cert", description = "import certificates to a keystore",
      mixinStandardHelpOptions = true)
  static class ImportCertCommand extends ShellBaseCommand {

    @Option(names = "--keystore", required = true, description = "keystore file")
    @Completion(FilePathCompleter.class)
    private String ksFile;

    @Option(names = "--type", required = true, description = "type of the keystore")
    @Completion(Completers.KeystoreTypeCompleter.class)
    private String ksType;

    @Option(names = "--password", description = "password of the keystore")
    private String ksPwdHint;

    @Option(names = {"--cert", "-c"}, required = true, split = ",",
        description = "certificate files")
    @Completion(FilePathCompleter.class)
    private List<String> certFiles;

    @Override
    public void run() {
      try {
        File realKsFile = new File(IoUtil.expandFilepath(ksFile));
        char[] password = readPasswordIfNotSet("Enter the keystore password", ksPwdHint);

        Set<String> aliases = new HashSet<>(10);
        KeyStore ks = null;
        PKCS12KeyStore pkcs12Ks = null;
        boolean isPkcs12Ks = StringUtil.orEqualsIgnoreCase(ksType, "PKCS12", "PKCS#12");

        if (realKsFile.exists()) {
          try (var inStream = Files.newInputStream(realKsFile.toPath())) {
            if (isPkcs12Ks) {
              pkcs12Ks = KeyUtil.loadPKCS12KeyStore(inStream, password);
            } else {
              ks = KeyUtil.loadKeyStore(ksType, inStream, password);
            }
          }

          Enumeration<String> strs = isPkcs12Ks ? pkcs12Ks.aliases() : ks.aliases();
          while (strs.hasMoreElements()) {
            aliases.add(strs.nextElement());
          }
        } else {
          if (isPkcs12Ks) {
            pkcs12Ks = KeyUtil.loadPKCS12KeyStore(null, null);
          } else {
            ks = KeyUtil.loadKeyStore(ksType, null, null);
          }
        }

        for (String certFile : certFiles) {
          X509Cert cert = X509Util.parseCert(new File(certFile));
          String baseAlias = X509Util.getCommonName(cert.subject());
          String alias = baseAlias;
          int idx = 2;
          while (aliases.contains(alias)) {
            alias = baseAlias + "-" + (idx++);
          }

          if (ks != null) {
            ks.setCertificateEntry(alias, new JceX509Certificate(cert.getCert()));
          } else {
            pkcs12Ks.setCertificateEntry(alias, cert.getCert());
          }
          aliases.add(alias);
        }

        try (ByteArrayOutputStream bout = new ByteArrayOutputStream(4096)) {
          if (ks != null) {
            ks.store(bout, password);
          } else {
            pkcs12Ks.store(bout, password);
          }
          saveVerbose("saved keystore to file", Paths.get(realKsFile.getPath()),
              bout.toByteArray());
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "export-cert-p7m", description = "export first certificate from CMS signed data",
      mixinStandardHelpOptions = true)
  static class ExportCertP7mCommand extends ShellBaseCommand {

    @Option(names = "--outform", description = "output format of the certificate")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Parameters(index = "0", description = "CMS signed data file")
    @Completion(FilePathCompleter.class)
    private String p7mFile;

    @Parameters(index = "1", description = "file to save the certificate")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Override
    public void run() {
      try {
        byte[] encodedCert = extractCertFromSignedData(IoUtil.read(p7mFile));
        saveVerbose("saved certificate to file", certFile, encodeCert(encodedCert, outform));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "export-keycert-pem", description = "export key and certificate from PEM file",
      mixinStandardHelpOptions = true)
  static class ExportKeyCertPemCommand extends ShellBaseCommand {

    @Option(names = "--outform", description = "output format of the key and certificate")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Parameters(index = "0", description = "PEM file containing key and certificate")
    @Completion(FilePathCompleter.class)
    private String pemFile;

    @Parameters(index = "1", description = "file to save the private key")
    @Completion(FilePathCompleter.class)
    private String keyFile;

    @Parameters(index = "2", description = "file to save the certificate")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Override
    public void run() {
      byte[] keyBytes = null;
      byte[] certBytes = null;

      try (PemReader reader = new PemReader(new FileReader(IoUtil.expandFilepath(pemFile)))) {
        PemObject pemObject;
        while ((pemObject = reader.readPemObject()) != null) {
          String type = pemObject.getType();
          if ("PRIVATE KEY".equals(type) && keyBytes == null) {
            keyBytes = pemObject.getContent();
          } else if ("CERTIFICATE".equals(type) && certBytes == null) {
            certBytes = pemObject.getContent();
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
        saveVerbose("certificate saved to file", certFile, encodeCert(certBytes, outform));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "export-keycert-est",
      description = "export key and certificate from EST response",
      mixinStandardHelpOptions = true)
  static class ExportKeyCertEstCommand extends ShellBaseCommand {

    @Option(names = "--outform", description = "output format of the key and certificate")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Parameters(index = "0", description = "EST response file")
    @Completion(FilePathCompleter.class)
    private String estRespFile;

    @Parameters(index = "1", description = "file to save the private key")
    @Completion(FilePathCompleter.class)
    private String keyFile;

    @Parameters(index = "2", description = "file to save the certificate")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Override
    public void run() {
      try (BufferedReader reader = new BufferedReader(new FileReader(
          IoUtil.expandFilepath(estRespFile)))) {
        String boundary = null;
        String line;
        while ((line = reader.readLine()) != null) {
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
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private static Object[] readBlock(BufferedReader reader, String boundary) throws IOException {
      StringBuilder sb = new StringBuilder();
      String line;
      String contentType = null;
      String encoding = null;
      boolean isLastBlock = false;
      boolean bodyStarted = false;
      boolean bodyFinished = false;

      while ((line = reader.readLine()) != null) {
        if (bodyStarted) {
          if (line.equals(boundary)) {
            bodyFinished = true;
            break;
          } else if (line.equals(boundary + "--")) {
            bodyFinished = true;
            isLastBlock = true;
            break;
          }
          sb.append(line).append("\r\n");
        } else if (line.isEmpty()) {
          bodyStarted = true;
        } else if (StringUtil.startsWithIgnoreCase(line, "content-type:")) {
          contentType = line.substring("content-type:".length()).trim();
        } else if (StringUtil.startsWithIgnoreCase(line, "content-transfer-encoding:")) {
          encoding = line.substring("content-transfer-encoding:".length()).trim();
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
  }

  private static byte[] extractCertFromSignedData(byte[] cmsBytes) throws IOException {
    ContentInfo ci = ContentInfo.getInstance(X509Util.toDerEncoded(cmsBytes));
    ASN1Set certs = SignedData.getInstance(ci.getContent()).getCertificates();
    if (certs == null || certs.size() == 0) {
      throw new IOException("Found no certificate");
    }
    return certs.getObjectAt(0).toASN1Primitive().getEncoded();
  }

  static char[] resolveP12Password(String passwordHint)
      throws IOException, PasswordResolverException {
    if (passwordHint != null) {
      return Passwords.resolvePassword(passwordHint);
    }
    Console console = System.console();
    if (console != null) {
      return console.readPassword("%s: ", "Enter the keystore password");
    }
    throw new IOException("password required");
  }

  abstract static class SecurityCommand extends ShellBaseCommand {

    protected Securities securities() throws Exception {
      return SecurityRuntime.get();
    }
  }

  @Command(name = "crl-info", description = "print CRL information",
      mixinStandardHelpOptions = true)
  static class CrlInfoCommand extends ShellBaseCommand {

    @Option(names = "--in", description = "CRL file", required = true)
    @Completion(FilePathCompleter.class)
    private String inFile;

    @Option(names = "--hex", description = "print hex number")
    private boolean hex;

    @Option(names = "--crlnumber", description = "print CRL number")
    private boolean crlNumber;

    @Option(names = "--issuer", description = "print issuer")
    private boolean issuer;

    @Option(names = "--this-update", description = "print thisUpdate")
    private boolean thisUpdate;

    @Option(names = "--next-update", description = "print nextUpdate")
    private boolean nextUpdate;

    @Override
    public void run() {
      try {
        CertificateList crl = CertificateList.getInstance(
                                X509Util.toDerEncoded(IoUtil.read(inFile)));
        String result;
        if (crlNumber) {
          ASN1Encodable asn1 = crl.getTBSCertList().getExtensions()
              .getExtensionParsedValue(OIDs.Extn.cRLNumber);
          result = asn1 == null ? "null"
                                : getNumber(ASN1Integer.getInstance(asn1).getPositiveValue());
        } else if (issuer) {
          result = crl.getIssuer().toString();
        } else if (thisUpdate) {
          result = toUtcTime(crl.getThisUpdate().getDate().toInstant());
        } else if (nextUpdate) {
          result = crl.getNextUpdate() == null ? "null"
              : toUtcTime(crl.getNextUpdate().getDate().toInstant());
        } else {
          result = crl.toString();
        }
        println(result);
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private String toUtcTime(Instant instant) {
      return DateUtil.toUtcTimeyyyyMMddhhmmss(instant) + "Z";
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
  }
}
