// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.type;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.certprofile.xijson.conf.GeneralNameType;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Configuration of GeneralName.
 *
 * @author Lijun Liao (xipki)
 *
 */

public class V1GeneralNameType {

  private static final Logger LOG =
      LoggerFactory.getLogger(V1GeneralNameType.class);

  private final List<String> modes;

  public V1GeneralNameType(List<String> modes) {
    this.modes = Args.notEmpty(modes, "modes");
  }

  public GeneralNameType toV2() {
    Set<GeneralNameTag> v2Modes = new HashSet<>(modes.size());
    for (String mode : modes) {
      if ("uniformResourceIdentifier".equalsIgnoreCase(mode)
          || "uri".equalsIgnoreCase(mode)) {
        v2Modes.add(GeneralNameTag.uri);
        continue;
      } else if ("x400Adress".equalsIgnoreCase(mode)
          || "x400Address".equalsIgnoreCase(mode)) {
        v2Modes.add(GeneralNameTag.x400Address);
        continue;
      } else {
        if (mode.toLowerCase(Locale.ROOT).startsWith("othername")) {
          int l = "othername".length();
          if (mode.length() > l) {
            LOG.warn("ignore the '{}' part in '{}'", mode.substring(l), mode);
          }
          v2Modes.add(GeneralNameTag.otherName);
          continue;
        }
      }

      for (GeneralNameTag t : GeneralNameTag.values()) {
        if (mode.equalsIgnoreCase(t.name())) {
          v2Modes.add(t);
          break;
        }
      }
    }

    return new GeneralNameType(v2Modes);
  }

  public static V1GeneralNameType parse(JsonMap json) throws CodecException {
    return new V1GeneralNameType(json.getNnStringList("modes"));
  }

}
