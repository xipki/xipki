// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.codec.json.JsonBuilder;
import org.xipki.codec.json.JsonEncodable;
import org.xipki.pkix.util.misc.StringUtil;

/**
 * Mgmt Message.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class MgmtMessage implements JsonEncodable {

  public byte[] getEncoded() {
    return StringUtil.toUtf8Bytes(JsonBuilder.toJson(toCodec()));
  }

}
