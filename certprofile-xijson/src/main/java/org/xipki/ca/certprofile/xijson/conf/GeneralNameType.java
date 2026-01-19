// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Configuration of GeneralName.
 *
 * @author Lijun Liao (xipki)
 *
 */

public class GeneralNameType implements JsonEncodable {

  private final Set<GeneralNameTag> modes;

  public GeneralNameType(Collection<GeneralNameTag> modes) {
    Args.notEmpty(modes, "modes");
    this.modes = (modes instanceof Set<?>) ?
        (Set<GeneralNameTag>) modes : new HashSet<>(modes);
  }

  public Set<GeneralNameTag> getModes() {
    return modes;
  }

  public void addTags(GeneralNameTag... tags) {
    for (GeneralNameTag tag : tags) {
      getModes().add(tag);
    }
  } // method addTags

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEnums("modes", modes);
  }

  public static GeneralNameType parse(JsonMap json) throws CodecException {
    Set<String> list = json.getStringSet("modes");
    Set<GeneralNameTag> tags = new HashSet<>();
    for (String v : list) {
      tags.add(GeneralNameTag.valueOf(v));
    }
    return new GeneralNameType(tags);
  }

}
