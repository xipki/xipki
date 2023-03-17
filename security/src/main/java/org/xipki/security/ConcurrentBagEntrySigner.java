// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.util.concurrent.ConcurrentBagEntry;

/**
 * A {@link ConcurrentBagEntry} for {@link XiContentSigner}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class ConcurrentBagEntrySigner extends ConcurrentBagEntry<XiContentSigner> {

  public ConcurrentBagEntrySigner(XiContentSigner value) {
    super(value);
  }

}
