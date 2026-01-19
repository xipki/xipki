// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.kpgen;

import org.xipki.ca.api.kpgen.KeypairGenerator;
import org.xipki.security.KeyInfoPair;
import org.xipki.security.KeySpec;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.conf.ConfPairs;

import java.io.IOException;
import java.security.KeyPair;
import java.security.SecureRandom;

/**
 * Software-based keypair generator.
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class SoftwareKeypairGenerator extends KeypairGenerator {

  private final SecureRandom random;

  public SoftwareKeypairGenerator(SecureRandom random) {
    this.random = random == null ? new SecureRandom() : random;
  }

  @Override
  public void initialize0(ConfPairs conf) {
  }

  @Override
  public KeyInfoPair generateKeypair(KeySpec keyspec)
      throws XiSecurityException {
    if (!supports(keyspec)) {
      throw new XiSecurityException(
          name + " cannot generate keypair of keyspec " + keyspec);
    }

    try {
      return generateKeypair0(keyspec);
    } catch (XiSecurityException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new XiSecurityException(ex);
    }
  }

  private KeyInfoPair generateKeypair0(KeySpec keyspec) throws Exception {
    KeyPair kp = KeyUtil.generateKeypair(keyspec, random);
    return new KeyInfoPair(kp);
  }

  @Override
  public boolean isHealthy() {
    return true;
  }

  @Override
  public void close() throws IOException {
  }

}
