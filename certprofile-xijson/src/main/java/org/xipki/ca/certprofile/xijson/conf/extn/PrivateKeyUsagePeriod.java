// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

/**
 * Extension PrivateKeyUsagePeriod.
 *
 * @author Lijun Liao (xipki)
 */

public class PrivateKeyUsagePeriod implements JsonEncodable {

  private final String validity;

  public PrivateKeyUsagePeriod(String validity) {
    this.validity = Args.notBlank(validity, "validity");
  }

  public String getValidity() {
    return validity;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("validity", validity);
  }

  public static PrivateKeyUsagePeriod parse(JsonMap json)
      throws CodecException {
    return new PrivateKeyUsagePeriod(json.getNnString("validity"));
  }

}
