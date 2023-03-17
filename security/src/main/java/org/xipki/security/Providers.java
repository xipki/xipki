// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.security.Security;

/**
 * Helper class to register providers {@link BouncyCastleProvider}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class Providers implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(Providers.class);

  public void init() {
    addBcProvider();
  }

  @Override
  public void close() {
  }

  private void addBcProvider() {
    if (Security.getProvider("BC") == null) {
      LOG.info("add BouncyCastleProvider");
      Security.addProvider(new BouncyCastleProvider());
    } else {
      LOG.info("BouncyCastleProvider already added");
    }
  }

}
