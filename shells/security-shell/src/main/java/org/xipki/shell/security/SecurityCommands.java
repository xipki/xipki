// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.security;

import org.xipki.codec.Base64;
import org.xipki.codec.Hex;
import org.xipki.codec.asn1.crypto.EncryptedPrivateKeyInfo;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.IoUtil;
import org.xipki.codec.util.StringUtil;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.pem.PemObject;
import org.xipki.crypto.core.pem.PemReader;
import org.xipki.pkix.Securities;
import org.xipki.pkix.asn1.cms.CertificateChoice;
import org.xipki.pkix.asn1.cms.ContentInfo;
import org.xipki.pkix.asn1.cms.SignedData;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.CertificateList;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.pkix.cert.JceX509Certificate;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.PKCS8Encryptor;
import org.xipki.pkix.util.X509Util;
import org.xipki.pkix.util.misc.CompareUtil;
import org.xipki.pkix.util.misc.PemEncoder;
import org.xipki.pkix.util.password.PasswordResolverException;
import org.xipki.pkix.util.password.Passwords;
import org.xipki.shell.Completion;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.xi.Completers;
import org.xipki.shell.xi.XiShellBaseCommand;
import org.xipki.util.misc.DateUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.ArrayList;
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

  @Command(name = "crypto-info", description = "print the crypto API service information",
      mixinStandardHelpOptions = true)
  static class CryptoInfoCommand extends XiShellBaseCommand {

    @Option(names = "--class", description = "print the qualified class name instead name")
    private boolean _class;

    @Override
    public void run() {
      try {
        CryptoApi cryptoApi = CryptoApiFactory.get();
        if (_class) {
          println(cryptoApi.getClass().getCanonicalName());
        } else {
          println(cryptoApi.name());
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "cert-info", description = "print certificate information",
      mixinStandardHelpOptions = true)
  static class CertInfoCommand extends XiShellBaseCommand {

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
  static class ConvertKeystoreCommand extends XiShellBaseCommand {

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

        char[] inPassword = readPasswordIfNotSet("password of the source keystore", inPwdHint);
        List<KsEntry> entries;
        try (var inStream = Files.newInputStream(realInFile.toPath())) {
          entries = readEntries(inType, inStream, inPassword);
        }

        boolean needsPassword = !("PEM".equalsIgnoreCase(outType)
            && "NONE".equalsIgnoreCase(outPwdHint));
        char[] outPassword = needsPassword
            ? readPasswordIfNotSet("password of the destination keystore", outPwdHint)
            : null;

        byte[] outBytes;
        try (ByteArrayOutputStream bout = new ByteArrayOutputStream(4096)) {
          if ("PEM".equalsIgnoreCase(outType)) {
            writePem(entries, bout, outPassword);
          } else if (isPkcs12(outType)) {
            Pkcs12KeyStore outKs = new Pkcs12KeyStore();
            for (KsEntry e : entries) {
              if (e.isKeyEntry()) {
                outKs.setKeyEntry(e.alias, e.privateKeyInfo(), e.certs);
              } else {
                outKs.setCertificateEntry(e.alias, e.certs.get(0));
              }
            }
            outKs.store(bout, outPassword);
          } else {
            KeyStore outKs = KeyUtil.loadKeyStore(outType, null, null);
            for (KsEntry e : entries) {
              if (e.isKeyEntry()) {
                outKs.setKeyEntry(e.alias, e.jceKey(), outPassword, toJceCerts(e.certs));
              } else {
                outKs.setCertificateEntry(e.alias, new JceX509Certificate(e.certs.get(0)));
              }
            }
            outKs.store(bout, outPassword);
          }
          outBytes = bout.toByteArray();
        }

        saveVerbose("saved destination keystore to file", realOutFile.toPath(), outBytes);
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    /**
     * An entry of a keystore: a key entry with its key and certificate chain, or a certificate
     * entry with its certificate.
     */
    private static final class KsEntry {

      private final String alias;

      /** The key read from a keystore of the JDK, or null. */
      private final Key jceKey;

      /** The private key read from a PKCS#12 keystore, or null. */
      private final PrivateKeyInfo privateKey;

      /** The certificate chain of a key entry (may be empty), or the certificate. */
      private final List<Certificate> certs;

      KsEntry(String alias, Key jceKey, PrivateKeyInfo privateKey, List<Certificate> certs) {
        this.alias = alias;
        this.jceKey = jceKey;
        this.privateKey = privateKey;
        this.certs = certs;
      }

      boolean isKeyEntry() {
        return jceKey != null || privateKey != null;
      }

      PrivateKeyInfo privateKeyInfo() throws CodecException {
        if (privateKey != null) {
          return privateKey;
        } else if (jceKey instanceof PrivateKey) {
          return PrivateKeyInfo.fromEncoded(jceKey.getEncoded());
        } else {
          throw new IllegalArgumentException("the key " + alias + " is not a private key, "
              + "it cannot be written to a PKCS#12 or PEM keystore");
        }
      }

      Key jceKey() throws InvalidKeySpecException {
        return (jceKey != null) ? jceKey : CryptoApiFactory.get().getPrivateKey(privateKey);
      }

    }

    private static boolean isPkcs12(String type) {
      return StringUtil.orEqualsIgnoreCase(type, "PKCS12", "PKCS#12");
    }

    private static List<KsEntry> readEntries(String type, InputStream in, char[] password)
        throws Exception {
      List<KsEntry> entries = new ArrayList<>();
      if (isPkcs12(type)) {
        Pkcs12KeyStore ks = KeyUtil.loadPKCS12KeyStore(in, password);
        for (String alias : ks.aliases()) {
          entries.add(ks.isKeyEntry(alias)
              ? new KsEntry(alias, null, ks.getKey(alias), ks.getCertificateChain(alias))
              : new KsEntry(alias, null, null, List.of(ks.getCertificate(alias))));
        }
      } else {
        KeyStore ks = KeyUtil.loadKeyStore(type, in, password);
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
          String alias = aliases.nextElement();
          if (ks.isKeyEntry(alias)) {
            entries.add(new KsEntry(alias, ks.getKey(alias, password), null,
                fromJceCerts(ks.getCertificateChain(alias))));
          } else {
            entries.add(new KsEntry(alias, null, null,
                fromJceCerts(new java.security.cert.Certificate[]{ks.getCertificate(alias)})));
          }
        }
      }
      return entries;
    }

    private static void writePem(List<KsEntry> entries, OutputStream out, char[] password)
        throws Exception {
      for (KsEntry e : entries) {
        if (e.isKeyEntry()) {
          PrivateKeyInfo key = e.privateKeyInfo();
          if (password == null) {
            out.write(PemEncoder.encode(key.getEncoded(), PemEncoder.PemLabel.PRIVATE_KEY));
          } else {
            EncryptedPrivateKeyInfo encKey = PKCS8Encryptor.encrypt(key, password);
            out.write(PemEncoder.encode(encKey.getEncoded(),
                PemEncoder.PemLabel.ENCRYPTED_PRIVATE_KEY));
          }
        }

        for (Certificate cert : e.certs) {
          out.write(PemEncoder.encode(cert.getEncoded(), PemEncoder.PemLabel.CERTIFICATE));
        }
      }
    }

    private static List<Certificate> fromJceCerts(java.security.cert.Certificate[] certs)
        throws CertificateEncodingException {
      List<Certificate> list = new ArrayList<>(certs == null ? 0 : certs.length);
      if (certs != null) {
        for (java.security.cert.Certificate cert : certs) {
          list.add(Certificate.fromJceCert((X509Certificate) cert));
        }
      }
      return list;
    }

    private static java.security.cert.Certificate[] toJceCerts(List<Certificate> certs)
        throws CertificateEncodingException {
      if (certs.isEmpty()) {
        return null;
      }

      java.security.cert.Certificate[] jceCerts = new java.security.cert.Certificate[certs.size()];
      for (int i = 0; i < jceCerts.length; i++) {
        jceCerts[i] = new JceX509Certificate(certs.get(i));
      }
      return jceCerts;
    }
  }

  @Command(name = "import-cert", description = "import certificates to a keystore",
      mixinStandardHelpOptions = true)
  static class ImportCertCommand extends XiShellBaseCommand {

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
        Pkcs12KeyStore pkcs12Ks = null;
        boolean isPkcs12Ks = StringUtil.orEqualsIgnoreCase(ksType, "PKCS12", "PKCS#12");

        if (realKsFile.exists()) {
          try (var inStream = Files.newInputStream(realKsFile.toPath())) {
            if (isPkcs12Ks) {
              pkcs12Ks = KeyUtil.loadPKCS12KeyStore(inStream, password);
            } else {
              ks = KeyUtil.loadKeyStore(ksType, inStream, password);
            }
          }

          if (isPkcs12Ks) {
            aliases.addAll(pkcs12Ks.aliases());
          } else {
            Enumeration<String> strs = ks.aliases();
            while (strs.hasMoreElements()) {
              aliases.add(strs.nextElement());
            }
          }
        } else {
          if (isPkcs12Ks) {
            pkcs12Ks = KeyUtil.loadPKCS12KeyStore((byte[]) null, null);
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
  static class ExportCertP7mCommand extends XiShellBaseCommand {

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
  static class ExportKeyCertPemCommand extends XiShellBaseCommand {

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
  static class ExportKeyCertEstCommand extends XiShellBaseCommand {

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

        Object[] blockInfo1 = readEstBlock(reader, boundary);
        if ((boolean) blockInfo1[0]) {
          throw new IOException("2 blocks is expected, found only 1");
        }

        Object[] blockInfo2 = readEstBlock(reader, boundary);
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

    private static Object[] readEstBlock(BufferedReader reader, String boundary)
        throws IOException {
      StringBuilder sb = new StringBuilder();
      String line;
      String contentType = null;
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
        }
      }

      if (!(bodyStarted && bodyFinished)) {
        throw new IOException("invalid block");
      }

      // RFC 8951: the parts are base64-encoded, any Content-Transfer-Encoding
      // header MUST be ignored.
      byte[] content = Base64.decodeFast(sb.toString());

      return new Object[]{isLastBlock, contentType, content};
    }
  }

  private static byte[] extractCertFromSignedData(byte[] cmsBytes) throws CodecException {
    ContentInfo ci = ContentInfo.fromEncoded(X509Util.toDerEncoded(cmsBytes));
    CertificateChoice.Set0 certs = SignedData.fromAsn1(ci.getContent().asSequence())
                                      .getCertificates();
    if (certs == null || certs.isEmpty()) {
      throw new CodecException("Found no certificate");
    }
    return certs.get(0).getEncoded();
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

  abstract static class SecurityCommand extends XiShellBaseCommand {

    protected Securities securities() throws Exception {
      return SecurityRuntime.get();
    }
  }

  @Command(name = "crl-info", description = "print CRL information",
      mixinStandardHelpOptions = true)
  static class CrlInfoCommand extends XiShellBaseCommand {

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
        CertificateList crl = CertificateList.fromEncoded(
            X509Util.toDerEncoded(IoUtil.read(inFile)));
        String result;
        if (crlNumber) {
          Extension extn = crl.getExtension(ExtensionOIDs.cRLNumber);
          result = extn == null ? "null" : getNumber(extn.cRLNumber());
        } else if (issuer) {
          result = crl.getIssuer().toString();
        } else if (thisUpdate) {
          result = toUtcTime(crl.thisUpdate());
        } else if (nextUpdate) {
          result = crl.getNextUpdate() == null ? "null" : toUtcTime(crl.nextUpdate());
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
