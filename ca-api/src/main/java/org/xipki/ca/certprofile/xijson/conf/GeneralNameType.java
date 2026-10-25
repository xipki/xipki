// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.json.JsonEncodable;
import org.xipki.codec.json.JsonMap;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * General Name Type definition.
 *
 * @author Lijun Liao (xipki)
 */
public class GeneralNameType implements JsonEncodable {

  private final Set<GeneralNameTag> modes;

  private final Set<String> otherNameTypes;

  public GeneralNameType(Collection<GeneralNameTag> modes) {
    this(modes, null);
  }

  public GeneralNameType(Collection<GeneralNameTag> modes,
                         Collection<String> otherNameTypes) {
    Args.notEmpty(modes, "modes");
    this.modes = (modes instanceof Set<?>) ? (Set<GeneralNameTag>) modes : new HashSet<>(modes);
    if (otherNameTypes == null) {
      this.otherNameTypes = null;
    } else {
      this.otherNameTypes = (otherNameTypes instanceof Set<?>) ? (Set<String>) otherNameTypes
                            : new HashSet<>(otherNameTypes);
    }
  }

  public Set<GeneralNameTag> modes() {
    return modes;
  }

  public Set<String> otherNameTypes() {
    return otherNameTypes;
  }

  public void addTags(GeneralNameTag... tags) {
    for (GeneralNameTag tag : tags) {
      modes().add(tag);
    }
  } // method addTags

  @Override
  public JsonMap toCodec() {
    JsonMap map = new JsonMap().putEnums("modes", modes, true);
    if (otherNameTypes != null) {
      map.putStrings("otherNameTypes", otherNameTypes);
    }
    return map;
  }

  public static GeneralNameType parse(JsonMap json) throws CodecException {
    Set<String> list = json.getStringSet("modes");
    Set<GeneralNameTag> tags = new HashSet<>();
    for (String v : list) {
      tags.add(GeneralNameTag.valueOf(v));
    }

    List<String> otherNameTypes = json.getStringList("otherNameTypes");
    return new GeneralNameType(tags, otherNameTypes);
  }

}
