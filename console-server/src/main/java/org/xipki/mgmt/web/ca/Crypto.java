// License Apache License 2.0

package org.xipki.mgmt.web.ca;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.security.auth.x500.X500Principal;

/**
 * JCA/JCE providers own all cryptography. This adapter only handles bounded standard containers.
 *
 * @author palos
 */
public final class Crypto {
  private static final Map<String, String> SIG_OIDS =
      Map.ofEntries(
          Map.entry("1.2.840.113549.1.1.5", "SHA1withRSA"),
          Map.entry("1.2.840.113549.1.1.11", "SHA256withRSA"),
          Map.entry("1.2.840.113549.1.1.12", "SHA384withRSA"),
          Map.entry("1.2.840.113549.1.1.13", "SHA512withRSA"),
          Map.entry("1.2.840.113549.1.1.10", "RSASSA-PSS"),
          Map.entry("1.2.840.10045.4.1", "SHA1withECDSA"),
          Map.entry("1.2.840.10045.4.3.2", "SHA256withECDSA"),
          Map.entry("1.2.840.10045.4.3.3", "SHA384withECDSA"),
          Map.entry("1.2.840.10045.4.3.4", "SHA512withECDSA"),
          Map.entry("1.2.840.10040.4.3", "SHA1withDSA"),
          Map.entry("2.16.840.1.101.3.4.3.2", "SHA256withDSA"),
          Map.entry("1.3.101.112", "Ed25519"),
          Map.entry("1.3.101.113", "Ed448"));
  private static final PSSParameterSpec DEFAULT_PSS =
      new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

  public static final class X509Cert {
    private final X509Certificate cert;

    public X509Cert(X509Certificate cert) {
      this.cert = Objects.requireNonNull(cert);
    }

    public byte[] getEncoded() {
      try {
        return cert.getEncoded();
      } catch (CertificateEncodingException ex) {
        throw new IllegalArgumentException(ex);
      }
    }

    public X509Certificate toJceCert() {
      return cert;
    }

    public X500Principal getSubject() {
      return cert.getSubjectX500Principal();
    }

    public X500Principal getIssuer() {
      return cert.getIssuerX500Principal();
    }

    public String getSubjectText() {
      return getSubject().getName();
    }

    public String getIssuerText() {
      return getIssuer().getName();
    }

    public Instant getNotBefore() {
      return cert.getNotBefore().toInstant();
    }

    public Instant getNotAfter() {
      return cert.getNotAfter().toInstant();
    }

    public BigInteger getSerialNumber() {
      return cert.getSerialNumber();
    }

    public int getBasicConstraints() {
      return cert.getBasicConstraints();
    }

    public boolean[] getKeyUsage() {
      return cert.getKeyUsage();
    }

    public PublicKey getPublicKey() {
      return cert.getPublicKey();
    }

    public EncodedKey getSubjectPublicKeyInfo() {
      return new EncodedKey(cert.getPublicKey());
    }

    public void verify(PublicKey key) throws GeneralSecurityException {
      cert.verify(key);
    }

    public boolean isSelfSigned() {
      if (!getSubject().equals(getIssuer())) {
        return false;
      }
      try {
        verify(getPublicKey());
        return true;
      } catch (Exception ex) {
        return false;
      }
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof X509Cert v && cert.equals(v.cert);
    }

    @Override
    public int hashCode() {
      return cert.hashCode();
    }
  }

  public static final class X509Crl {
    private final X509CRL crl;

    public X509Crl(byte[] bytes) throws GeneralSecurityException {
      Der.single(bytes, 48);
      var in = new ByteArrayInputStream(bytes);
      crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(in);
      if (in.available() != 0) {
        throw new CRLException("Trailing CRL data");
      }
    }

    public byte[] getEncoded() throws CRLException {
      return crl.getEncoded();
    }

    public BigInteger getCrlNumber() {
      byte[] bytes = crl.getExtensionValue("2.5.29.20");
      return bytes == null
          ? null
          : new BigInteger(Der.single(Der.single(bytes, 4).content(), 2).content());
    }
  }

  public record EncodedKey(PublicKey key) {
    public byte[] getEncoded() {
      return key.getEncoded();
    }
  }

  public static final class X509Util {
    public static X509Cert parseCert(byte[] bytes) throws CertificateException {
      byte[] der = decodePem(bytes, "CERTIFICATE");
      Der.single(der, 48);
      var in = new ByteArrayInputStream(der);
      var cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
      if (in.available() != 0) {
        throw new CertificateException("Trailing certificate data");
      }
      return new X509Cert(cert);
    }

    public static List<X509Cert> parseCerts(byte[] bytes) throws CertificateException {
      if (bytes.length > Der.LIMIT) {
        throw new CertificateException("Oversized certificates");
      }
      var list = new ArrayList<X509Cert>();
      String text = new String(bytes, StandardCharsets.US_ASCII).strip();
      while (!text.isEmpty()) {
        String end = "-----END CERTIFICATE-----";
        if (!text.startsWith("-----BEGIN CERTIFICATE-----")) {
          throw new CertificateException("Invalid certificate bundle");
        }
        int i = text.indexOf(end);
        if (i < 0) {
          throw new CertificateException("Incomplete PEM");
        }
        list.add(
            parseCert(text.substring(0, i + end.length()).getBytes(StandardCharsets.US_ASCII)));
        if (list.size() > 32) {
          throw new CertificateException("Too many certificates");
        }
        text = text.substring(i + end.length()).strip();
      }
      return list;
    }
  }

  public static byte[] decodePem(byte[] bytes, String label) {
    if (bytes == null || bytes.length > Der.LIMIT) {
      throw new IllegalArgumentException("Oversized material");
    }
    if (bytes.length == 0 || bytes[0] == 48) {
      return bytes;
    }
    String text = new String(bytes, StandardCharsets.US_ASCII).strip(),
        begin = "-----BEGIN " + label + "-----",
        end = "-----END " + label + "-----";
    if (!text.startsWith(begin) || !text.endsWith(end)) {
      throw new IllegalArgumentException("Invalid PEM label");
    }
    String data =
        text.substring(begin.length(), text.length() - end.length()).replaceAll("[\\r\\n\\t ]", "");
    return Base64.getDecoder().decode(data);
  }

  public record Csr(byte[] encoded, X500Principal subject, EncodedKey subjectPublicKeyInfo) {
    public byte[] getEncoded() {
      return encoded.clone();
    }

    public X500Principal getSubject() {
      return subject;
    }

    public EncodedKey getSubjectPublicKeyInfo() {
      return subjectPublicKeyInfo;
    }
  }

  public static Csr csr(byte[] input) throws GeneralSecurityException {
    byte[] der = decodePem(input, "CERTIFICATE REQUEST");
    Der.validate(der);
    var outer = Der.single(der, 48).reader();
    var info = outer.read(48);
    var alg = outer.read(48).reader();
    String oid = Der.oid(alg.read(6));
    String sigAlgorithm = SIG_OIDS.get(oid);
    if (sigAlgorithm == null) {
      throw new IllegalArgumentException("Unsupported CSR signature algorithm");
    }
    PSSParameterSpec pss = null;
    if (sigAlgorithm.equals("RSASSA-PSS")) {
      var parameters = AlgorithmParameters.getInstance("RSASSA-PSS");
      try {
        parameters.init(alg.read(48).encoded());
      } catch (IOException ex) {
        throw new IllegalArgumentException("Invalid PSS parameters", ex);
      }
      pss = parameters.getParameterSpec(PSSParameterSpec.class);
      if (!Set.of("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512")
              .contains(pss.getDigestAlgorithm())
          || !"MGF1".equalsIgnoreCase(pss.getMGFAlgorithm())
          || pss.getSaltLength() < 0
          || pss.getSaltLength() > 1024
          || pss.getTrailerField() != 1) {
        throw new IllegalArgumentException("Unsupported PSS parameters");
      }
    } else if (sigAlgorithm.endsWith("RSA") && alg.hasNext()) {
      var nil = alg.read(5);
      if (nil.content().length != 0) {
        throw new IllegalArgumentException("Invalid algorithm parameters");
      }
    }
    alg.end();
    var bits = outer.read(3);
    outer.end();
    if (bits.content().length < 2 || bits.content()[0] != 0) {
      throw new IllegalArgumentException("Invalid CSR signature bits");
    }
    var body = info.reader();
    var version = body.read(2);
    if (!Arrays.equals(version.content(), new byte[] {0})) {
      throw new IllegalArgumentException("Unsupported CSR version");
    }
    var subject = body.read(48);
    var spki = body.read(48);
    var attrs = body.read(160);
    body.end();
    // Verify the shallow attribute containers and reject malformed/trailing encodings.
    var attributeReader = attrs.reader();
    int count = 0;
    while (attributeReader.hasNext()) {
      if (++count > 64) {
        throw new IllegalArgumentException("Too many CSR attributes");
      }
      var a = attributeReader.read(48).reader();
      Der.oid(a.read(6));
      var values = a.read(49).reader();
      int n = 0;
      while (values.hasNext()) {
        if (++n > 64) {
          throw new IllegalArgumentException("Too many attribute values");
        }
        values.read();
      }
      a.end();
    }
    PublicKey key = publicKey(spki.encoded());
    var signature = Signature.getInstance(sigAlgorithm);
    if (pss != null) {
      signature.setParameter(pss);
    }
    signature.initVerify(key);
    signature.update(info.encoded());
    if (!signature.verify(Arrays.copyOfRange(bits.content(), 1, bits.content().length))) {
      throw new IllegalArgumentException("Invalid CSR signature");
    }
    return new Csr(der, new X500Principal(subject.encoded()), new EncodedKey(key));
  }

  private static String keyAlgorithm(String oid) {
    return switch (oid) {
      case "1.2.840.113549.1.1.1" -> "RSA";
      case "1.2.840.113549.1.1.10" -> "RSASSA-PSS";
      case "1.2.840.10045.2.1" -> "EC";
      case "1.2.840.10040.4.1" -> "DSA";
      case "1.3.101.112" -> "Ed25519";
      case "1.3.101.113" -> "Ed448";
      default -> throw new IllegalArgumentException("Unsupported key algorithm OID: " + oid);
    };
  }

  public static PublicKey publicKey(byte[] spki) throws GeneralSecurityException {
    var r = Der.single(spki, 48).reader();
    var alg = r.read(48).reader();
    String type = keyAlgorithm(Der.oid(alg.read(6)));
    r.read(3);
    r.end();
    return KeyFactory.getInstance(type).generatePublic(new X509EncodedKeySpec(spki));
  }

  public static PrivateKey privateKey(byte[] pkcs8) throws GeneralSecurityException {
    var r = Der.single(pkcs8, 48).reader();
    r.read(2);
    var alg = r.read(48).reader();
    String type = keyAlgorithm(Der.oid(alg.read(6)));
    r.read(4);
    while (r.hasNext()) {
      var optional = r.read();
      if (optional.tag() != 160 && optional.tag() != 161 && optional.tag() != 129) {
        throw new IllegalArgumentException("Invalid private key container");
      }
    }
    return KeyFactory.getInstance(type).generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
  }

  public static String signatureAlgorithm(PrivateKey key) {
    String algorithm = key.getAlgorithm();
    if (key instanceof EdECPrivateKey ed) {
      return ed.getParams().getName();
    }
    return switch (algorithm) {
      case "RSA" -> "SHA256withRSA";
      case "RSASSA-PSS" -> "RSASSA-PSS";
      case "DSA" -> "SHA256withDSA";
      case "EC" -> "SHA256withECDSA";
      default -> throw new IllegalArgumentException("Unsupported signing key: " + algorithm);
    };
  }

  public static Signature signature(String algorithm) throws GeneralSecurityException {
    var signature = Signature.getInstance(algorithm);
    if (algorithm.equals("RSASSA-PSS")) {
      signature.setParameter(DEFAULT_PSS);
    }
    return signature;
  }

  public static byte[] csr(
      X500Principal subject, PublicKey key, PrivateKey privateKey, String algorithm)
      throws GeneralSecurityException {
    byte[] info =
        Der.sequence(
            Der.integer(BigInteger.ZERO),
            subject.getEncoded(),
            key.getEncoded(),
            Der.tagged(160, new byte[0]));
    return signed(info, privateKey, algorithm);
  }

  private static byte[] algorithm(String algorithm) throws GeneralSecurityException {
    String oid =
        SIG_OIDS.entrySet().stream()
            .filter(e -> e.getValue().equals(algorithm))
            .map(Map.Entry::getKey)
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Unsupported signature algorithm"));
    if (algorithm.equals("RSASSA-PSS")) {
      var parameters = AlgorithmParameters.getInstance("RSASSA-PSS");
      parameters.init(DEFAULT_PSS);
      try {
        return Der.sequence(Der.oid(oid), parameters.getEncoded());
      } catch (IOException ex) {
        throw new GeneralSecurityException(ex);
      }
    }
    return algorithm.endsWith("RSA")
        ? Der.sequence(Der.oid(oid), Der.tagged(5, new byte[0]))
        : Der.sequence(Der.oid(oid));
  }

  private static byte[] signed(byte[] info, PrivateKey key, String algorithm)
      throws GeneralSecurityException {
    var signature = signature(algorithm);
    signature.initSign(key);
    signature.update(info);
    return Der.sequence(info, algorithm(algorithm), Der.bits(signature.sign()));
  }

  /** A temporary self-signed certificate is required by the PKCS12 key-entry container. */
  public static X509Cert placeholder(KeyPair key) throws GeneralSecurityException {
    return issue(
        key.getPublic(),
        key.getPrivate(),
        "CN=Pending CA enrollment",
        "CN=Pending CA enrollment",
        new BigInteger(128, new SecureRandom()).add(BigInteger.ONE),
        Instant.now().minusSeconds(60),
        Instant.now().plusSeconds(86400),
        List.of());
  }

  public static X509Cert issue(
      PublicKey publicKey,
      PrivateKey issuerKey,
      String subject,
      String issuer,
      BigInteger serial,
      Instant from,
      Instant to,
      List<byte[]> extensions)
      throws GeneralSecurityException {
    String algorithm = signatureAlgorithm(issuerKey);
    var fields = new ArrayList<byte[]>();
    fields.add(Der.tagged(160, Der.integer(BigInteger.TWO)));
    fields.add(Der.integer(serial));
    fields.add(algorithm(algorithm));
    fields.add(new X500Principal(issuer).getEncoded());
    var format = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
    fields.add(
        Der.sequence(
            Der.tagged(24, format.format(from).getBytes(StandardCharsets.US_ASCII)),
            Der.tagged(24, format.format(to).getBytes(StandardCharsets.US_ASCII))));
    fields.add(new X500Principal(subject).getEncoded());
    fields.add(publicKey.getEncoded());
    if (!extensions.isEmpty()) {
      fields.add(Der.tagged(163, Der.sequence(extensions.toArray(byte[][]::new))));
    }
    return X509Util.parseCert(
        signed(Der.sequence(fields.toArray(byte[][]::new)), issuerKey, algorithm));
  }

  public static String keySpec(EncodedKey key) throws GeneralSecurityException {
    var k = key.key();
    if (k instanceof RSAPublicKey r) {
      return Set.of(2048, 3072, 4096).contains(r.getModulus().bitLength())
          ? "RSA-" + r.getModulus().bitLength()
          : null;
    }
    if (k instanceof ECPublicKey e) {
      for (String name : List.of("secp256r1", "secp384r1", "secp521r1")) {
        var params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(name));
        var expected = params.getParameterSpec(ECParameterSpec.class);
        var actual = e.getParams();
        if (expected.getCurve().equals(actual.getCurve())
            && expected.getGenerator().equals(actual.getGenerator())
            && expected.getOrder().equals(actual.getOrder())
            && expected.getCofactor() == actual.getCofactor()) {
          return name.toUpperCase(Locale.ROOT);
        }
      }
      return null;
    }
    if (k instanceof EdECPublicKey ed) {
      return ed.getParams().getName().toUpperCase(Locale.ROOT);
    }
    return null;
  }

  private Crypto() {}
}
