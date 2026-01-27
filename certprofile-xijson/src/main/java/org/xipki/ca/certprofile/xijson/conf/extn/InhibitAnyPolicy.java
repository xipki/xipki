// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

/**
 * Extension InhibitAnyPolicy.
 *
 * @author Lijun Liao (xipki)
 */

public class InhibitAnyPolicy implements JsonEncodable {

  private final int skipCerts;

  public int getSkipCerts() {
    return skipCerts;
  }

  public InhibitAnyPolicy(int skipCerts) {
    this.skipCerts = skipCerts;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("skipCerts", skipCerts);
  }

  public static InhibitAnyPolicy parse(JsonMap json) throws CodecException {
    return new InhibitAnyPolicy(json.getNnInt("skipCerts"));
  }

}
