// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.kpgen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.KeyInfoPair;
import org.xipki.security.KeySpec;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.misc.StringUtil;

import java.io.Closeable;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Keypair generator.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public abstract class KeypairGenerator implements Closeable {

  private static final Logger LOG =
      LoggerFactory.getLogger(KeypairGenerator.class);

  protected String name;

  protected final Set<KeySpec> keyspecs = new HashSet<>();

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
        Set<String> tokens = StringUtil.splitAsSet(
            str.toUpperCase(Locale.ROOT), ": \t");
        assert tokens != null;
        for (String token : tokens) {
          try {
            KeySpec keySpec = KeySpec.ofKeySpec(token);
            keyspecs.add(keySpec);
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

  protected abstract void initialize0(ConfPairs conf)
      throws XiSecurityException;

  public boolean supports(KeySpec keyspec) {
    return keyspec != null && keyspecs.contains(keyspec);
  }

  public abstract KeyInfoPair generateKeypair(KeySpec keyspec)
      throws XiSecurityException;

  public abstract boolean isHealthy();

}
