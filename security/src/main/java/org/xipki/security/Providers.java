// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.security.util.KeyUtil;

import java.io.Closeable;

/**
 * Providers.
 *
 * @author Lijun Liao (xipki)
 */
public class Providers implements Closeable {

  public void init() {
    KeyUtil.addProviders();
  }

  @Override
  public void close() {
  }

}
