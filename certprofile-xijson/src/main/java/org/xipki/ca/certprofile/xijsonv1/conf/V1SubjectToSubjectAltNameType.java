// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf;

import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableOid;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

import java.util.Arrays;
import java.util.List;

/**
 * Control which RDNs and how they are converted to the SubjectAltNames
 * extension.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class V1SubjectToSubjectAltNameType {

  private static final List<GeneralNameTag> allowedTargets = Arrays.asList(
      GeneralNameTag.rfc822Name,
      GeneralNameTag.DNSName,
      GeneralNameTag.directoryName,
      GeneralNameTag.uri,
      GeneralNameTag.IPAddress,
      GeneralNameTag.registeredID);

  private final DescribableOid source;

  private final GeneralNameTag target;

  public V1SubjectToSubjectAltNameType(
      DescribableOid source, GeneralNameTag target) {
    this.source = Args.notNull(source, "source");
    this.target = Args.notNull(target, "target");
    if (!allowedTargets.contains(target)) {
      throw new IllegalArgumentException(
          "target " + target + " is not allowed");
    }
  }

  public DescribableOid getSource() {
    return source;
  }

  public GeneralNameTag getTarget() {
    return target;
  }

  public static V1SubjectToSubjectAltNameType parse(JsonMap json)
      throws CodecException {
    return new V1SubjectToSubjectAltNameType(
        DescribableOid.parseNn(json, "source"),
        GeneralNameTag.getGeneralNameTag(json.getNnString("target")));
  }

}
