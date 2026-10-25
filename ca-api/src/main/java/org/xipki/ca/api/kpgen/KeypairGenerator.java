// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.kpgen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.KeyInfoPair;
import org.xipki.codec.ConfPairs;
import org.xipki.pkix.util.misc.StringUtil;

import java.io.Closeable;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Keypair Generator.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class KeypairGenerator implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(KeypairGenerator.class);

  protected String name;

  protected final Set<KeySpec> keyspecs = new HashSet<>();

  public String name() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  /**
   * Initializes me.
   * @param conf
   *          Configuration. Could be {@code null}.
   * @throws XiSecurityException
   *         if error during the initialization occurs.
   */
  public void initialize(String conf) throws XiSecurityException {
    ConfPairs pairs = (conf == null) ? null : new ConfPairs(conf);

    boolean allowsAllKeySpecs = true;
    if (pairs != null) {
      String str = pairs.value("keyspecs");

      if (StringUtil.isNotBlank(str)) {
        allowsAllKeySpecs = false;
        Set<String> tokens = StringUtil.splitAsSet(str.toUpperCase(Locale.ROOT), ": \t");
        assert tokens != null;
        for (String token : tokens) {
          try {
            keyspecs.add(KeySpec.ofKeySpec(token));
          } catch (NoSuchAlgorithmException e) {
            LOG.warn("ignored unknown keyspec {}", token);
          }
        }
      }
    }

    if (allowsAllKeySpecs) {
      keyspecs.addAll(Arrays.asList(KeySpec.values()));
    }

    initialize0(pairs);
  }

  protected abstract void initialize0(ConfPairs conf) throws XiSecurityException;

  public boolean supports(KeySpec keyspec) {
    return keyspec != null && keyspecs.contains(keyspec);
  }

  public abstract KeyInfoPair generateKeypair(KeySpec keyspec) throws XiSecurityException;

  public abstract boolean isHealthy();

}
