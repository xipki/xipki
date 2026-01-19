// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.ca.api.profile.ctrl.ExtKeyUsageControl;
import org.xipki.ca.api.profile.id.AbstractID;
import org.xipki.ca.api.profile.id.ExtendedKeyUsageID;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CollectionUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Extension ExtendedKeyUsage.
 *
 * @author Lijun Liao (xipki)
 */

public class ExtendedKeyUsage implements JsonEncodable {

  private final List<ExtendedKeyUsageID> required;

  private final List<ExtendedKeyUsageID> optional;

  public ExtendedKeyUsage(List<ExtendedKeyUsageID> required,
                          List<ExtendedKeyUsageID> optional) {
    if (CollectionUtil.isEmpty(required) && CollectionUtil.isEmpty(optional)) {
      throw new IllegalArgumentException(
          "required and optional can not both be empty");
    }

    this.required = required;
    this.optional = optional;
  }

  public List<ExtendedKeyUsageID> getRequired() {
    return required;
  }

  public List<ExtendedKeyUsageID> getOptional() {
    return optional;
  }

  public Set<ExtKeyUsageControl> toXiExtKeyUsageOptions() {
    Set<ExtKeyUsageControl> controls = new HashSet<>();

    if (required != null) {
      for (ExtendedKeyUsageID usage : required) {
        controls.add(new ExtKeyUsageControl(usage.getOid(), true));
      }
    }

    if (optional != null) {
      for (ExtendedKeyUsageID usage : optional) {
        controls.add(new ExtKeyUsageControl(usage.getOid(), false));
      }
    }

    return Collections.unmodifiableSet(controls);
  } // method buildExtKeyUsageOptions

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();
    if (required != null) {
      ret.putStrings("required", AbstractID.toJsonStringList(required));
    }

    if (optional != null) {
      ret.putStrings("optional", AbstractID.toJsonStringList(optional));
    }
    return ret;
  }

  public static ExtendedKeyUsage parse(JsonMap json) throws CodecException {
    return new ExtendedKeyUsage(
        toUsageIDList(json.getStringList("required")),
        toUsageIDList(json.getStringList("optional")));
  }

  private static List<ExtendedKeyUsageID> toUsageIDList(List<String> list) {
    if (list == null) {
      return null;
    }

    List<ExtendedKeyUsageID> usages = new ArrayList<>(list.size());
    for (String v : list) {
      usages.add(ExtendedKeyUsageID.ofOidOrName(v));
    }
    return usages;
  }

} // class ExtendedKeyUsage
