// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.util.JSON;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public abstract class SdkMessage {

  public byte[] encode() {
    return JSON.toJSONBytes(this);
  }

}
