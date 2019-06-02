/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.scep.client;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.xipki.scep.util.ScepHashAlgo;
import org.xipki.util.Args;

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
  boolean isTrusted(X509Certificate cert);

  /**
   * CA certificate validator with caching certificates.
   */

  public static final class CachingCertificateValidator implements CaCertValidator {

    private final ConcurrentHashMap<String, Boolean> cachedAnswers;

    private final CaCertValidator delegate;

    public CachingCertificateValidator(CaCertValidator delegate) {
      this.delegate = Args.notNull(delegate, "delegate");
      this.cachedAnswers = new ConcurrentHashMap<String, Boolean>();
    }

    @Override
    public boolean isTrusted(X509Certificate cert) {
      Args.notNull(cert, "cert");
      String hexFp;
      try {
        hexFp = ScepHashAlgo.SHA256.hexDigest(cert.getEncoded());
      } catch (CertificateEncodingException ex) {
        return false;
      }

      Boolean bo = cachedAnswers.get(hexFp);

      if (bo != null) {
        return bo.booleanValue();
      } else {
        boolean answer = delegate.isTrusted(cert);
        cachedAnswers.put(hexFp, answer);
        return answer;
      }
    }

  }

  /**
   * {@link CaCertValidator} with pre-povisioned CA certificates.
   *
   */
  public static final class PreprovisionedCaCertValidator implements CaCertValidator {

    private final Set<String> fpOfCerts;

    public PreprovisionedCaCertValidator(X509Certificate cert) {
      Args.notNull(cert, "cert");
      fpOfCerts = new HashSet<String>(1);

      String hexFp;
      try {
        hexFp = ScepHashAlgo.SHA256.hexDigest(cert.getEncoded());
      } catch (CertificateEncodingException ex) {
        throw new IllegalArgumentException("at least one of the certificate could not be encoded");
      }

      fpOfCerts.add(hexFp);
    }

    public PreprovisionedCaCertValidator(Set<X509Certificate> certs) {
      Args.notEmpty(certs, "certs");
      fpOfCerts = new HashSet<String>(certs.size());

      for (X509Certificate m : certs) {
        String hexFp;
        try {
          hexFp = ScepHashAlgo.SHA256.hexDigest(m.getEncoded());
        } catch (CertificateEncodingException ex) {
          throw new IllegalArgumentException(
              "at least one of the certificate could not be encoded");
        }

        fpOfCerts.add(hexFp);
      }
    }

    @Override
    public boolean isTrusted(X509Certificate cert) {
      Args.notNull(cert, "cert");

      try {
        String hextFp = ScepHashAlgo.SHA256.hexDigest(cert.getEncoded());
        return fpOfCerts.contains(hextFp);
      } catch (CertificateEncodingException ex) {
        return false;
      }
    }

  }

  public static final class PreprovisionedHashCaCertValidator implements CaCertValidator {

    private final ScepHashAlgo hashAlgo;

    private final Set<byte[]> hashValues;

    public PreprovisionedHashCaCertValidator(ScepHashAlgo hashAlgo, Set<byte[]> hashValues) {
      this.hashAlgo = Args.notNull(hashAlgo, "hashAlgo");
      Args.notEmpty(hashValues, "hashValues");

      final int hLen = hashAlgo.getLength();
      for (byte[] m : hashValues) {
        if (m.length != hLen) {
          throw new IllegalArgumentException("invalid the length of hashValue: "
              + m.length + " != " + hLen);
        }
      }

      this.hashValues = new HashSet<byte[]>(hashValues.size());
      for (byte[] m : hashValues) {
        this.hashValues.add(Arrays.copyOf(m, m.length));
      }
    }

    @Override
    public boolean isTrusted(X509Certificate cert) {
      Args.notNull(cert, "cert");
      byte[] actual;
      try {
        actual = hashAlgo.digest(cert.getEncoded());
      } catch (CertificateEncodingException ex) {
        return false;
      }

      for (byte[] m : hashValues) {
        if (Arrays.equals(actual, m)) {
          return true;
        }
      }

      return false;
    }

  }

}
