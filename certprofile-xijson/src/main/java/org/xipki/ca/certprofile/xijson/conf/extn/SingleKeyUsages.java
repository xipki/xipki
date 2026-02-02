// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.ca.api.profile.ctrl.KeySingleUsage;
import org.xipki.ca.certprofile.xijson.KeyUsageControl;
import org.xipki.security.KeySpec;
import org.xipki.security.pkix.KeyUsage;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CollectionUtil;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Single Key Usages.
 *
 * @author Lijun Liao (xipki)
 */

public class SingleKeyUsages implements JsonEncodable {

  private List<KeySpec> appliesTo;

  private List<KeyUsage> required;

  private List<KeyUsage> optional;

  public SingleKeyUsages(List<KeySpec> appliesTo, List<KeyUsage> required,
                         List<KeyUsage> optional) {
    if (CollectionUtil.isEmpty(required) && CollectionUtil.isEmpty(optional)) {
      throw new IllegalArgumentException(
          "required and optional can not both be empty");
    }

    this.appliesTo = appliesTo;
    this.required = required;
    this.optional = optional;
  }

  public void setRequired(List<KeyUsage> required) {
    this.required = required;
  }

  public List<KeyUsage> required() {
    return required;
  }

  public void setAppliesTo(List<KeySpec> appliesTo) {
    this.appliesTo = appliesTo;
  }

  public List<KeySpec> appliesTo() {
    return appliesTo;
  }

  public void setOptional(List<KeyUsage> optional) {
    this.optional = optional;
  }

  public List<KeyUsage> optional() {
    return optional;
  }

  public KeyUsageControl.KeySingleUsages toXiKeyUsageOptions() {
    Set<KeySingleUsage> controls = new HashSet<>();

    if (required != null) {
      for (KeyUsage usage : required) {
        controls.add(new KeySingleUsage(usage, true));
      }
    }

    if (optional != null) {
      for (KeyUsage usage : optional) {
        controls.add(new KeySingleUsage(usage, false));
      }
    }

    return new KeyUsageControl.KeySingleUsages(appliesTo, controls);
  }

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();
    if (appliesTo != null) {
      List<String> list = new ArrayList<>(appliesTo.size());
      for (KeySpec v : appliesTo) {
        list.add(v.name().replace('_', '-'));
      }
      ret.putStrings("appliesTo", list);
    }

    ret.putEnums("required", required);
    ret.putEnums("optional", optional);
    return ret;
  }

  public static SingleKeyUsages parse(JsonMap json) throws CodecException {
    List<KeySpec> appliesTo = null;
    List<String> list = json.getStringList("appliesTo");
    if (list != null) {
      appliesTo = new ArrayList<>();
      for (String v : list) {
        try {
          appliesTo.add(KeySpec.ofKeySpec(v));
        } catch (NoSuchAlgorithmException e) {
          throw new CodecException(e);
        }
      }
    }

    list = json.getStringList("required");
    List<KeyUsage> required = (list == null) ? null : toKeyUsages(list);

    list = json.getStringList("optional");
    List<KeyUsage> optional = (list == null) ? null : toKeyUsages(list);

    return new SingleKeyUsages(appliesTo, required, optional);
  }

  private static List<KeyUsage> toKeyUsages(List<String> usageTexts) {
    List<KeyUsage> ret = new ArrayList<>(usageTexts.size());
    for (String v : usageTexts) {
      ret.add(KeyUsage.getKeyUsage(v));
    }
    return ret;
  }

}
