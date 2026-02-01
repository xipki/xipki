// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

/**
 * Extension PolicyConstraints.
 *
 * @author Lijun Liao (xipki)
 */

public class PolicyConstraints implements JsonEncodable {

  private final Integer requireExplicitPolicy;

  private final Integer inhibitPolicyMapping;

  public PolicyConstraints(Integer requireExplicitPolicy,
                           Integer inhibitPolicyMapping) {
    // Only for CA, at least one of requireExplicitPolicy and
    // inhibitPolicyMapping must be present
    if (requireExplicitPolicy == null && inhibitPolicyMapping == null) {
      throw new IllegalArgumentException("requireExplicitPolicy and " +
          "inhibitPolicyMapping may not be both null");
    }

    this.requireExplicitPolicy = requireExplicitPolicy;
    this.inhibitPolicyMapping = inhibitPolicyMapping;
  }

  public Integer requireExplicitPolicy() {
    return requireExplicitPolicy;
  }

  public Integer inhibitPolicyMapping() {
    return inhibitPolicyMapping;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("requireExplicitPolicy", requireExplicitPolicy)
        .put("inhibitPolicyMapping",  inhibitPolicyMapping);
  }

  public static PolicyConstraints parse(JsonMap json) throws CodecException {
    return new PolicyConstraints(json.getInt("requireExplicitPolicy"),
        json.getInt("inhibitPolicyMapping"));
  }

}
