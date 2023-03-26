// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.xipki.password.PasswordResolver;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;

import java.io.Closeable;
import java.math.BigInteger;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.*;

/**
 * Concurrent keypair generator.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
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
  public void initialize(String conf, PasswordResolver passwordResolver) throws XiSecurityException {
    ConfPairs pairs = (conf == null) ? null : new ConfPairs(conf);
    if (pairs != null) {
      String str = pairs.value("RSA.E");
      if (StringUtil.isNotBlank(str)) {
        rsaE = StringUtil.toBigInt(str);
      }
    }

    if (rsaE == null) {
      rsaE = RSAKeyGenParameterSpec.F4;
    }

    Set<String> tokens = null;
    if (pairs != null) {
      String str = pairs.value("keyspecs");
      if (StringUtil.isNotBlank(str)) {
        tokens = StringUtil.splitAsSet(str.toUpperCase(Locale.ROOT), ": \t");
      }
    }

    if (tokens == null) {
      tokens = new HashSet<>(Arrays.asList("RSA", "EC", "DSA", "ED25519", "ED448", "X25519", "X448"));
    }

    for (String token : tokens) {
      try {
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
              ASN1ObjectIdentifier curveId = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName);
              if (curveId != null) {
                String keyspec = "EC/" + curveId.getId();
                keyspecs.add(keyspec);
              }
            }
            break;
          default:
            if (token.startsWith("EC/")) {
              String nameOrOid = token.substring(3);
              ASN1ObjectIdentifier curveId = AlgorithmUtil.getCurveOidForCurveNameOrOid(nameOrOid);
              if (curveId == null) {
                throw new XiSecurityException("invalid keyspec " + token);
              } else {
                String keyspec = "EC/" + curveId.getId();
                keyspecs.add(keyspec);
              }
            } else if (token.startsWith("RSA/")) {
              int keysize = Integer.parseInt(token.substring(4));
              keyspecs.add("RSA/" + keysize);
            } else if (token.startsWith("DSA/")) {
              String[] strs = token.substring(4).split("/");
              int pSize = Integer.parseInt(strs[0]);
              int qSize = Integer.parseInt(strs[0]);
              keyspecs.add("DSA/" + pSize + "/" + qSize);
            } else {
              keyspecs.add(token);
            }
        }
      } catch (RuntimeException e) {
        throw new XiSecurityException("invalid keyspec " + token);
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
   *         if could not generate keypair.
   */
  public abstract PrivateKeyInfo generateKeypair(String keyspec) throws XiSecurityException;

  public abstract boolean isHealthy();

}
