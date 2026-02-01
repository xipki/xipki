// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

/**
 * Extension BasicConstraints.
 *
 * @author Lijun Liao (xipki)
 */

public class BasicConstraints implements JsonEncodable {

  private final int pathLen;

  public BasicConstraints(int pathLen) {
    this.pathLen = Args.notNegative(pathLen, "pathLen");
  }

  public int pathLen() {
    return pathLen;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("pathLen", pathLen);
  }

  public static BasicConstraints parse(JsonMap json) throws CodecException {
    return new BasicConstraints(json.getNnInt("pathLen"));
  }

} // class BasicConstraints
