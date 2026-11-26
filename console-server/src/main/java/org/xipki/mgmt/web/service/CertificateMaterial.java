// License Apache License 2.0

package org.xipki.mgmt.web.service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.ca.Crypto;
import org.xipki.mgmt.web.ca.Crypto.*;
import org.xipki.mgmt.web.core.*;

/**
 * Request-scoped conversion only: key material never leaves memory or enters logs.
 *
 * @author palos
 */
public final class CertificateMaterial {
  private CertificateMaterial() {}

  public static void checkRequestSize(long length) {
    if (length > 8L * 1024 * 1024) {
      throw new ApiException(413, "Payload too large");
    }
  }

  public static byte[] upload(Upload file) {
    if (file.isEmpty()) {
      throw new IllegalArgumentException("Missing certificate material");
    }
    if (file.getSize() > 2L * 1024 * 1024) {
      throw new ApiException(413, "Payload too large");
    }
    try {
      return file.getBytes();
    } catch (Exception ex) {
      throw new IllegalArgumentException("Invalid certificate material");
    }
  }

  public static byte[] csr(Upload file) {
    byte[] bytes = upload(file);
    try {
      var csr = Crypto.csr(bytes);
      return csr.getEncoded();
    } catch (Exception ex) {
      throw new IllegalArgumentException("Invalid CSR");
    }
  }

  public static byte[] certificate(Upload file, byte[] csrBytes) {
    byte[] bytes = upload(file);
    try {
      var target = X509Util.parseCert(bytes);
      var csr = Crypto.csr(csrBytes);
      var holder = target;
      if (!csr.getSubject().equals(holder.getSubject())
          || !Arrays.equals(
              csr.getSubjectPublicKeyInfo().getEncoded(),
              holder.getSubjectPublicKeyInfo().getEncoded())) {
        throw new IllegalArgumentException("CSR and target certificate mismatch");
      }
      return target.getEncoded();
    } catch (Exception ex) {
      throw new IllegalArgumentException("Invalid target certificate or mismatched CSR");
    }
  }

  public static Instant time(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      if (!value.endsWith("Z")) {
        throw new IllegalArgumentException("UTC required");
      }
      return Instant.parse(value);
    } catch (Exception ex) {
      throw new IllegalArgumentException("Invalid UTC time");
    }
  }

  public static void range(Instant from, Instant to) {
    if (from != null && to != null && !from.isBefore(to)) {
      throw new IllegalArgumentException("Invalid time range");
    }
  }

  public static String required(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("Missing required value");
    }
    return value;
  }

  public static void requireKeypairGenerator(CaManager manager, String ca) throws CaMgmtException {
    CaEntry entry = manager.getCa(ca);
    if (entry == null
        || entry.getBase().getKeypairGenNames() == null
        || entry.getBase().getKeypairGenNames().stream()
            .noneMatch(name -> name != null && !name.isBlank())) {
      throw new ApiException(
          409,
          "CA has no keypair generator configured; assign one in CA Management before server-side"
              + " key generation");
    }
  }

  public static BigInteger serial(String value) {
    if (value == null || !value.matches("[0-9a-fA-F]+")) {
      throw new IllegalArgumentException("Invalid hexadecimal serial");
    }
    BigInteger serial = new BigInteger(value, 16);
    if (serial.signum() <= 0) {
      throw new IllegalArgumentException("Invalid serial");
    }
    return serial;
  }

  public static byte[] pkcs12(KeyCertBytesPair pair, List<X509Cert> caChain, char[] password)
      throws Exception {
    try {
      var key = Crypto.privateKey(pair.getKey());
      var certificates = new ArrayList<Certificate>();
      var leaf = X509Util.parseCert(pair.getCert());
      String algorithm = Crypto.signatureAlgorithm(key);
      var proof = Crypto.signature(algorithm);
      byte[] challenge = new byte[32];
      new SecureRandom().nextBytes(challenge);
      proof.initSign(key);
      proof.update(challenge);
      byte[] signed = proof.sign();
      proof.initVerify(leaf.getPublicKey());
      proof.update(challenge);
      if (!proof.verify(signed)) {
        throw new IllegalArgumentException("Private key and certificate mismatch");
      }
      var factory = CertificateFactory.getInstance("X.509");
      certificates.add(factory.generateCertificate(new ByteArrayInputStream(pair.getCert())));
      if (caChain != null) {
        for (var ca : caChain) {
          var certificate = factory.generateCertificate(new ByteArrayInputStream(ca.getEncoded()));
          if (!certificates.contains(certificate)) {
            certificates.add(certificate);
          }
        }
      }
      var store = KeyStore.getInstance("PKCS12");
      store.load(null, password);
      store.setKeyEntry("certificate", key, password, certificates.toArray(Certificate[]::new));
      var output = new ByteArrayOutputStream();
      store.store(output, password);
      return output.toByteArray();
    } finally {
      Arrays.fill(password, '\0');
      Arrays.fill(pair.getKey(), (byte) 0);
    }
  }
}
