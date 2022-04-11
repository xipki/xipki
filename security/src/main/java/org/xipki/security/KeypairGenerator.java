/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.xipki.password.PasswordResolver;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;

import java.io.Closeable;
import java.math.BigInteger;
import java.util.*;

/**
 * Concurrent keypair generator.
 *
 * @author Lijun Liao
 * @since 5.4.0
 */

public abstract class KeypairGenerator implements Closeable {

  protected String name;

  protected BigInteger rsaE;

  protected final Set<String> keyspecs = new HashSet<>();

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  /**
   * Initializes me.
   * @param conf
   *          Configuration. Could be {@code null}.
   * @param passwordResolver
   *          Password resolver. Could be {@code null}.
   * @throws XiSecurityException
   *         if error during the initialization occurs.
   */
  protected void initialize(String conf, PasswordResolver passwordResolver)
      throws XiSecurityException {
    ConfPairs pairs = (conf == null) ? null : new ConfPairs(conf);
    if (pairs != null) {
      String str = pairs.value("RSA.E");
      if (StringUtil.isNotBlank(str)) {
        rsaE = StringUtil.toBigInt(str);
      }
    }

    if (rsaE == null) {
      rsaE = BigInteger.valueOf(0x10001);
    }

    Set<String> tokens = null;
    if (pairs != null) {
      String str = pairs.value("keyspecs");
      if (StringUtil.isNotBlank(str)) {
        tokens = StringUtil.splitAsSet(str.toUpperCase(Locale.ROOT), ": \t");
      }
    }

    if (tokens == null) {
      tokens = new HashSet<>(
          Arrays.asList("RSA", "EC", "DSA", "ED25519", "ED448", "X25519", "X448"));
    }

    for (String token : tokens) {
      if (token.indexOf('/') != -1) {
        keyspecs.add(token);
        continue;
      }

      switch (token) {
        case "RSA":
          for (int i = 2; i < 9; i++) {
            keyspecs.add("RSA/" + (i * 1024));
          }
          break;
        case "DSA":
          keyspecs.add("DSA/1024/160");
          keyspecs.add("DSA/2048/224");
          keyspecs.add("DSA/2048/256");
          keyspecs.add("DSA/3072/256");
          break;
        case "EC":
          List<String> curveNames = AlgorithmUtil.getECCurveNames();
          for (String curveName : curveNames) {
            ASN1ObjectIdentifier curveId =
                AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName);
            if (curveId != null) {
              String keyspec = "EC/" + curveId.getId();
              keyspecs.add(keyspec);
            }
          }
          break;
        default:
          keyspecs.add(token);
      }
    }

    initialize0(pairs, passwordResolver);
  }

  protected abstract void initialize0(ConfPairs conf, PasswordResolver passwordResolver)
      throws XiSecurityException;

  public boolean supports(String keyspec) {
    return keyspec != null && keyspecs.contains(keyspec.toUpperCase(Locale.ROOT));
  }

  /**
   * Generate keypair for the given keyspec as defined in RFC 5958.
   *
   * @param keyspec
   *         Key specification. It has the following format:
   *         <ul>
   *         <li>RSA:   'RSA/'&lt;bit-length&gt; or 'RSA/'&lt;bit-length&gt;</li>
   *         <li>DSA:   'DSA/'&lt;bit-lenth of P&gt;'/'&lt;bit-lenth of Q&gt;</li>
   *         <li>EC:    'EC/'&lt;curve OID&gt;</li>
   *         <li>EdDSA: 'ED25519' or 'ED448'</li>
   *         <li>XDH:   'X25519' or 'X448'</li>
   *         </ul>
   * @return the generated keypair.
   * @throws XiSecurityException
   *         if could not generated keypair.
   */
  public abstract PrivateKeyInfo generateKeypair(String keyspec)
      throws XiSecurityException;

  public abstract boolean isHealthy();

}
