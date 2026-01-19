// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

/**
 * Extension CCC simple ExtensionSchema.
 *
 * @author Lijun Liao (xipki)
 *
 */

public class CCCSimpleExtensionSchema implements JsonEncodable {

  private final int version;

  public CCCSimpleExtensionSchema(int version) {
    this.version = version;
  }

  public int getVersion() {
    return version;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("version", version);
  }

  public static CCCSimpleExtensionSchema parse(JsonMap json)
      throws CodecException {
    return new CCCSimpleExtensionSchema(json.getNnInt("version"));
  }

}
