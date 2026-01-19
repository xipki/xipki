// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

/**
 * Extension AuthorityInfoAccess.
 *
 * @author Lijun Liao (xipki)
 */

public class AuthorityInfoAccess implements JsonEncodable {

  private final boolean includeCaIssuers;

  private final boolean includeOcsp;

  public AuthorityInfoAccess(boolean includeCaIssuers, boolean includeOcsp) {
    this.includeCaIssuers = includeCaIssuers;
    this.includeOcsp = includeOcsp;
  }

  public boolean isIncludeCaIssuers() {
    return includeCaIssuers;
  }

  public boolean isIncludeOcsp() {
    return includeOcsp;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("includeCaIssuers", includeCaIssuers)
        .put("includeOcsp", includeOcsp);
  }

  public static AuthorityInfoAccess parse(JsonMap json) throws CodecException {
    return new AuthorityInfoAccess(
        json.getBool("includeCaIssuers", false),
        json.getBool("includeOcsp", false));
  }

}
