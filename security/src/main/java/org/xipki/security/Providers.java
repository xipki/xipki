// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.xipki.security.util.KeyUtil;

import java.io.Closeable;

/**
 * Helper class to register providers.
 *
 * @author Lijun Liao (xipki)
 */
@Component
public class Providers implements Closeable {

  @Activate
  public void init() {
    KeyUtil.addProviders();
  }

  @Deactivate
  @Override
  public void close() {
  }

}
