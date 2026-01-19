// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.misc.StringUtil;

/**
 * CA Management message via the REST API.
 *
 * @author Lijun Liao (xipki)
 */

public abstract class MgmtMessage implements JsonEncodable {

  public byte[] getEncoded() {
    return StringUtil.toUtf8Bytes(JsonBuilder.toJson(toCodec()));
  }

}
