// License Apache License 2.0

package org.xipki.mgmt.web.ca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.*;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.xipki.mgmt.web.ca.CaDomain.KeyCertBytesPair;
import org.xipki.mgmt.web.ca.Crypto.EncodedKey;
import org.xipki.mgmt.web.core.Upload;
import org.xipki.mgmt.web.service.CertificateMaterial;

/**
 * @author palos
 */
class CryptoTest {
  private static KeyPair key(String algorithm) throws Exception {
    var g = KeyPairGenerator.getInstance(algorithm);
    if (algorithm.equals("RSA") || algorithm.equals("DSA")) {
      g.initialize(2048);
    }
    if (algorithm.equals("EC")) {
      g.initialize(new ECGenParameterSpec("secp256r1"));
    }
    return g.generateKeyPair();
  }

  @Test
  void verifiesExistingJdkCsrSignatureAlgorithmsAndPrivateKeys() throws Exception {
    for (String algorithm : List.of("RSA", "EC", "DSA", "Ed25519", "Ed448")) {
      var key = key(algorithm);
      String signature =
          switch (algorithm) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            case "DSA" -> "SHA256withDSA";
            default -> algorithm;
          };
      byte[] der =
          Crypto.csr(
              new X500Principal("CN=CSR Fixture"), key.getPublic(), key.getPrivate(), signature);
      var csr = Crypto.csr(der);
      assertEquals(new X500Principal("CN=CSR Fixture"), csr.getSubject());
      assertArrayEquals(key.getPublic().getEncoded(), csr.getSubjectPublicKeyInfo().getEncoded());
      assertArrayEquals(der, CertificateMaterial.csr(upload(der)));
      assertArrayEquals(
          key.getPrivate().getEncoded(),
          Crypto.privateKey(key.getPrivate().getEncoded()).getEncoded());
      byte[] bad = der.clone();
      bad[bad.length - 1] ^= 1;
      assertThrows(Exception.class, () -> Crypto.csr(bad), algorithm);
    }
  }

  @Test
  void verifiesRsaPssUsingJdkParameters() throws Exception {
    var pair = key("RSA");
    byte[] csr =
        Crypto.csr(new X500Principal("CN=PSS"), pair.getPublic(), pair.getPrivate(), "RSASSA-PSS");
    assertArrayEquals(
        pair.getPublic().getEncoded(), Crypto.csr(csr).getSubjectPublicKeyInfo().getEncoded());
  }

  @Test
  void rejectsMalformedDerAndAppendedContentBeforeUse() throws Exception {
    var pair = key("EC");
    byte[] csr =
        Crypto.csr(
            new X500Principal("CN=Malformed"),
            pair.getPublic(),
            pair.getPrivate(),
            "SHA256withECDSA");
    assertThrows(Exception.class, () -> Crypto.csr(Arrays.copyOf(csr, csr.length - 1)));
    assertThrows(Exception.class, () -> Crypto.csr(Der.join(csr, new byte[] {0})));
    assertThrows(Exception.class, () -> Crypto.csr(new byte[] {48, (byte) 128, 0, 0}));
    assertThrows(Exception.class, () -> Der.single(new byte[] {48, (byte) 129, 0}, 48));
    assertThrows(Exception.class, () -> Der.single(new byte[Der.LIMIT + 1], 48));
  }

  @Test
  void curveClassificationComparesParametersRatherThanFieldSize() throws Exception {
    var pair = key("EC");
    var original = (ECPublicKey) pair.getPublic();
    assertEquals("SECP256R1", Crypto.keySpec(new EncodedKey(original)));
    var params = original.getParams();
    var wrong =
        new ECParameterSpec(
            params.getCurve(),
            new ECPoint(
                params.getGenerator().getAffineX(),
                params.getGenerator().getAffineY().add(BigInteger.ONE)),
            params.getOrder(),
            params.getCofactor());
    ECPublicKey forged =
        new ECPublicKey() {
          public ECPoint getW() {
            return original.getW();
          }

          public ECParameterSpec getParams() {
            return wrong;
          }

          public String getAlgorithm() {
            return "EC";
          }

          public String getFormat() {
            return "X.509";
          }

          public byte[] getEncoded() {
            return original.getEncoded();
          }
        };
    assertNull(Crypto.keySpec(new EncodedKey(forged)));
  }

  @Test
  void requiresCsrCertificateAndPkcs12KeyBinding() throws Exception {
    var pair = key("RSA");
    var other = key("RSA");
    byte[] csr =
        Crypto.csr(
            new X500Principal("CN=Pending CA enrollment"),
            pair.getPublic(),
            pair.getPrivate(),
            "SHA256withRSA");
    var cert = Crypto.placeholder(pair);
    assertArrayEquals(
        cert.getEncoded(), CertificateMaterial.certificate(upload(cert.getEncoded()), csr));
    assertThrows(
        IllegalArgumentException.class,
        () -> CertificateMaterial.certificate(upload(Crypto.placeholder(other).getEncoded()), csr));
    byte[] encodedKey = other.getPrivate().getEncoded();
    assertThrows(
        Exception.class,
        () ->
            CertificateMaterial.pkcs12(
                new KeyCertBytesPair(encodedKey, cert.getEncoded()),
                List.of(),
                "download password 123".toCharArray()));
    assertArrayEquals(new byte[encodedKey.length], encodedKey);
    byte[] p12 =
        CertificateMaterial.pkcs12(
            new KeyCertBytesPair(pair.getPrivate().getEncoded(), cert.getEncoded()),
            List.of(),
            "download password 123".toCharArray());
    var store = KeyStore.getInstance("PKCS12");
    store.load(new ByteArrayInputStream(p12), "download password 123".toCharArray());
    assertNotNull(store.getKey("certificate", "download password 123".toCharArray()));
  }

  private static Upload upload(byte[] data) {
    return new Upload() {
      public byte[] getBytes() {
        return data;
      }

      public long getSize() {
        return data.length;
      }

      public boolean isEmpty() {
        return data.length == 0;
      }

      public String getOriginalFilename() {
        return "fixture";
      }

      public String getContentType() {
        return "application/octet-stream";
      }
    };
  }
}
