// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client;

import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CA Certificate validator.
 *
 * @author Lijun Liao
 *
 */

public interface CaCertValidator {

  /**
   * Whether the certificate can be trusted.
   * @param cert
   *          Target certificate.
   * @return whether the certificate is trusted.
   */
  boolean isTrusted(X509Cert cert);

  /**
   * CA certificate validator with caching certificates.
   */

  final class CachingCertificateValidator implements CaCertValidator {

    private final ConcurrentHashMap<String, Boolean> cachedAnswers;

    private final CaCertValidator delegate;

    public CachingCertificateValidator(CaCertValidator delegate) {
      this.delegate = Args.notNull(delegate, "delegate");
      this.cachedAnswers = new ConcurrentHashMap<>();
    }

    @Override
    public boolean isTrusted(X509Cert cert) {
      Args.notNull(cert, "cert");
      String hexFp = HashAlgo.SHA256.hexHash(cert.getEncoded());
      Boolean bo = cachedAnswers.get(hexFp);

      if (bo != null) {
        return bo;
      } else {
        boolean answer = delegate.isTrusted(cert);
        cachedAnswers.put(hexFp, answer);
        return answer;
      }
    }

  } // class CachingCertificateValidator

  /**
   * {@link CaCertValidator} with pre-povisioned CA certificates.
   *
   */
  final class PreprovisionedCaCertValidator implements CaCertValidator {

    private final Set<String> fpOfCerts;

    public PreprovisionedCaCertValidator(X509Cert cert) {
      Args.notNull(cert, "cert");
      fpOfCerts = new HashSet<>(1);
      fpOfCerts.add(HashAlgo.SHA256.hexHash(cert.getEncoded()));
    }

    public PreprovisionedCaCertValidator(Set<X509Cert> certs) {
      Args.notEmpty(certs, "certs");
      fpOfCerts = new HashSet<>(certs.size());

      for (X509Cert m : certs) {
        fpOfCerts.add(HashAlgo.SHA256.hexHash(m.getEncoded()));
      }
    }

    @Override
    public boolean isTrusted(X509Cert cert) {
      String hextFp = HashAlgo.SHA256.hexHash(Args.notNull(cert, "cert").getEncoded());
      return fpOfCerts.contains(hextFp);
    }

  } // class PreprovisionedCaCertValidator

  final class PreprovisionedHashCaCertValidator implements CaCertValidator {

    private final HashAlgo hashAlgo;

    private final Set<byte[]> hashValues;

    public PreprovisionedHashCaCertValidator(HashAlgo hashAlgo, Set<byte[]> hashValues) {
      this.hashAlgo = Args.notNull(hashAlgo, "hashAlgo");
      Args.notEmpty(hashValues, "hashValues");

      final int hLen = hashAlgo.getLength();
      for (byte[] m : hashValues) {
        if (m.length != hLen) {
          throw new IllegalArgumentException("invalid the length of hashValue: " + m.length + " != " + hLen);
        }
      }

      this.hashValues = new HashSet<>(hashValues.size());
      for (byte[] m : hashValues) {
        this.hashValues.add(Arrays.copyOf(m, m.length));
      }
    }

    @Override
    public boolean isTrusted(X509Cert cert) {
      byte[] actual = hashAlgo.hash(Args.notNull(cert, "cert").getEncoded());

      for (byte[] m : hashValues) {
        if (Arrays.equals(actual, m)) {
          return true;
        }
      }

      return false;
    }

  } // class PreprovisionedHashCaCertValidator

}
