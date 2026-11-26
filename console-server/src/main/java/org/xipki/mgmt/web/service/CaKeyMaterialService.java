// License Apache License 2.0

package org.xipki.mgmt.web.service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import org.xipki.codec.util.ConfPairs;
import org.xipki.mgmt.web.ca.Crypto;
import org.xipki.mgmt.web.ca.Crypto.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.CaKeyRequest;

/**
 * Creates canonical, in-memory signer configuration; never resolves client file references.
 *
 * @author palos
 */
public class CaKeyMaterialService {
  public static final int MATERIAL_LIMIT = 2 * 1024 * 1024;

  public record Material(String type, String conf) {
    @Override
    public String toString() {
      return "CA signer material [redacted]";
    }
  }

  public CaKeyMaterialService() {}

  public Material prepare(CaKeyRequest request, X509Cert expected, boolean allowGenerate) {
    if (request == null || request.mode == null) {
      throw new IllegalArgumentException("Signer material required");
    }
    try {
      if ("pkcs11".equals(request.mode)) {
        return pkcs11(request);
      }
      KeyStore store;
      char[] inputPassword;
      if ("generate".equals(request.mode) && allowGenerate) {
        String algorithm = Objects.requireNonNullElse(request.algorithm, "RSA3072");
        KeyPairGenerator generator;
        if (Set.of("RSA2048", "RSA3072", "RSA4096").contains(algorithm)) {
          generator = KeyPairGenerator.getInstance("RSA");
          generator.initialize(Integer.parseInt(algorithm.substring(3)));
        } else if (Set.of("EC_P256", "EC_P384").contains(algorithm)) {
          generator = KeyPairGenerator.getInstance("EC");
          generator.initialize(
              new ECGenParameterSpec(algorithm.equals("EC_P256") ? "secp256r1" : "secp384r1"));
        } else {
          throw new IllegalArgumentException("Unsupported key algorithm");
        }
        var pair = generator.generateKeyPair();
        inputPassword = randomPassword().toCharArray();
        store = KeyStore.getInstance("PKCS12");
        store.load(null, inputPassword);
        store.setKeyEntry(
            "main",
            pair.getPrivate(),
            inputPassword,
            new Certificate[] {Crypto.placeholder(pair).toJceCert()});
      } else if ("pkcs12".equals(request.mode)) {
        inputPassword = Objects.requireNonNullElse(request.password, "").toCharArray();
        store = KeyStore.getInstance("PKCS12");
        store.load(new ByteArrayInputStream(decode(request.pkcs12)), inputPassword);
      } else {
        throw new IllegalArgumentException("Unsupported signer mode");
      }

      try {
        List<String> aliases =
            Collections.list(store.aliases()).stream()
                .filter(
                    alias -> {
                      try {
                        return store.isKeyEntry(alias);
                      } catch (KeyStoreException ex) {
                        return false;
                      }
                    })
                .toList();
        String alias = request.keyAlias;
        if (alias == null || alias.isBlank()) {
          if (aliases.size() != 1) {
            throw new IllegalArgumentException("Select a key alias");
          }
          alias = aliases.get(0);
        }
        if (!aliases.contains(alias)) {
          throw new IllegalArgumentException("Invalid key alias");
        }
        var key = store.getKey(alias, inputPassword);
        if (!(key instanceof PrivateKey privateKey)) {
          throw new IllegalArgumentException("Private key required");
        }
        var certificate = store.getCertificate(alias);
        if (certificate == null) {
          throw new IllegalArgumentException("Key certificate required");
        }
        String algorithm =
            signatureAlgorithm(privateKey.getAlgorithm(), request.signatureAlgorithm);
        Signature signature = Signature.getInstance(algorithm);
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);
        signature.initSign(privateKey);
        signature.update(challenge);
        byte[] proof = signature.sign();
        signature.initVerify(
            expected == null ? certificate.getPublicKey() : expected.getPublicKey());
        signature.update(challenge);
        if (!signature.verify(proof)) {
          throw new IllegalArgumentException("CA key does not match certificate");
        }

        // Repackage only the selected key; don't transmit unrelated keys or the supplied password.
        String password = randomPassword();
        KeyStore selected = KeyStore.getInstance("PKCS12");
        selected.load(null, password.toCharArray());
        selected.setKeyEntry(
            "main", privateKey, password.toCharArray(), store.getCertificateChain(alias));
        var output = new ByteArrayOutputStream();
        selected.store(output, password.toCharArray());
        var pairs =
            new ConfPairs()
                .putPair("algo", algorithm)
                .putPair("password", password)
                .putPair("key-label", "main")
                .putPair(
                    "keystore",
                    "base64:" + Base64.getEncoder().encodeToString(output.toByteArray()));
        return new Material("PKCS12", pairs.getEncoded());
      } finally {
        Arrays.fill(inputPassword, '\0');
      }
    } catch (ApiException | IllegalArgumentException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new IllegalArgumentException("Invalid CA signer material");
    }
  }

  private static String signatureAlgorithm(String keyAlgorithm, String requested) {
    String defaultAlgorithm =
        "RSA".equalsIgnoreCase(keyAlgorithm) ? "SHA256withRSA" : "SHA256withECDSA";
    String algorithm = requested == null ? defaultAlgorithm : requested;
    Set<String> permitted =
        "RSA".equalsIgnoreCase(keyAlgorithm)
            ? Set.of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA")
            : Set.of("SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA");
    if (!permitted.contains(algorithm)) {
      throw new IllegalArgumentException("Unsupported signature algorithm");
    }
    return algorithm;
  }

  public Material complete(String canonicalConf, X509Cert certificate, List<X509Cert> issuers) {
    try {
      var pairs = new ConfPairs(canonicalConf);
      var input = new CaKeyRequest();
      input.mode = "pkcs12";
      input.pkcs12 = pairs.value("keystore").substring(7);
      input.password = pairs.value("password");
      input.keyAlias = "main";
      input.signatureAlgorithm = pairs.value("algo");
      var verified = new ConfPairs(prepare(input, certificate, false).conf());
      char[] password = verified.value("password").toCharArray();
      try {
        var selected = KeyStore.getInstance("PKCS12");
        selected.load(
            new ByteArrayInputStream(
                Base64.getDecoder().decode(verified.value("keystore").substring(7))),
            password);
        var chain = new ArrayList<Certificate>();
        chain.add(certificate.toJceCert());
        if (issuers != null) {
          for (var issuer : issuers) {
            chain.add(issuer.toJceCert());
          }
        }
        selected.setKeyEntry(
            "main", selected.getKey("main", password), password, chain.toArray(Certificate[]::new));
        var output = new ByteArrayOutputStream();
        selected.store(output, password);
        verified.putPair(
            "keystore", "base64:" + Base64.getEncoder().encodeToString(output.toByteArray()));
        return new Material("PKCS12", verified.getEncoded());
      } finally {
        Arrays.fill(password, '\0');
      }
    } catch (Exception ex) {
      throw new IllegalArgumentException("Cannot complete CA signer material");
    }
  }

  private static Material pkcs11(CaKeyRequest r) {
    // Module names refer exclusively to the CA's preinstalled module registry; no paths/PIN
    // loading.
    if (r.module == null
        || !r.module.matches("[a-zA-Z0-9_.-]{1,64}")
        || r.slotIndex == null
        || r.slotIndex < 0) {
      throw new IllegalArgumentException("Invalid module/slot");
    }
    if ((r.keyId == null) == (r.keyLabel == null)) {
      throw new IllegalArgumentException("Select key ID or label");
    }
    var pairs = new ConfPairs().putPair("module", r.module).putPair("slot", r.slotIndex.toString());
    String algorithm = Objects.requireNonNullElse(r.signatureAlgorithm, "SHA256withRSA");
    if (!Set.of(
            "SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA256withECDSA", "SHA384withECDSA")
        .contains(algorithm)) {
      throw new IllegalArgumentException("Unsupported signature algorithm");
    }
    pairs.putPair("algo", algorithm);
    if (r.keyId != null) {
      if (!r.keyId.matches("[0-9a-fA-F]+") || r.keyId.length() % 2 != 0) {
        throw new IllegalArgumentException("Invalid key ID");
      }
      pairs.putPair("key-id", r.keyId);
    } else {
      if (r.keyLabel.isBlank() || r.keyLabel.length() > 256) {
        throw new IllegalArgumentException("Invalid key label");
      }
      pairs.putPair("key-label", r.keyLabel);
    }
    return new Material("PKCS11", pairs.getEncoded());
  }

  public static byte[] decode(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("Material required");
    }
    if (value.length() > (MATERIAL_LIMIT * 4L / 3 + 8)) {
      throw new ApiException(413, "Payload too large");
    }
    byte[] bytes =
        value.stripLeading().startsWith("-----BEGIN")
            ? value.strip().getBytes(StandardCharsets.US_ASCII)
            : Base64.getDecoder().decode(value);
    if (bytes.length > MATERIAL_LIMIT) {
      throw new ApiException(413, "Payload too large");
    }
    return bytes;
  }

  public static X509Cert certificate(String value) {
    try {
      return X509Util.parseCert(decode(value));
    } catch (ApiException | IllegalArgumentException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new IllegalArgumentException("Invalid certificate");
    }
  }

  public static List<X509Cert> certificates(List<String> values) {
    if (values == null) {
      return null;
    }
    var result = new ArrayList<X509Cert>();
    for (String value : values) {
      byte[] bytes = decode(value);
      try {
        if (new String(bytes, StandardCharsets.US_ASCII).stripLeading().startsWith("-----BEGIN")) {
          var bundle = X509Util.parseCerts(bytes);
          if (bundle.isEmpty()) {
            throw new IllegalArgumentException("Certificate chain is empty");
          }
          result.addAll(bundle);
        } else {
          result.add(X509Util.parseCert(bytes));
        }
      } catch (Exception ex) {
        throw new IllegalArgumentException("Invalid certificate chain");
      }
    }
    return result;
  }

  public static void requireCa(X509Cert certificate) {
    try {
      var cert = certificate.toJceCert();
      boolean[] usage = cert.getKeyUsage();
      if (cert.getBasicConstraints() < 0 || usage == null || usage.length <= 5 || !usage[5]) {
        throw new IllegalArgumentException("CA certificate with keyCertSign required");
      }
    } catch (IllegalArgumentException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new IllegalArgumentException("Invalid CA certificate");
    }
  }

  private static String randomPassword() {
    byte[] bytes = new byte[32];
    new SecureRandom().nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
