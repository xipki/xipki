// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.type;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * Integer with description.
 *
 * @author Lijun Liao (xipki)
 */
public class DescribableInt extends V1Describable {

  private final int value;

  public DescribableInt(String description, int value) {
    super(description);
    this.value = value;
  }

  /**
   * Gets the value of the value property.
   *
   * @return the value of the value property.
   */
  public int value() {
    return value;
  }

  public static DescribableInt parse(JsonMap json) throws CodecException {
    return new DescribableInt(json.getString("description"),
        json.getNnInt("value"));
  }

  public static DescribableInt parseNn(JsonMap json, String key)
      throws CodecException {
    DescribableInt v = parse(json, key);
    if (v == null) {
      throw new CodecException(key + " is not present");
    }
    return v;
  }

  public static DescribableInt parse(JsonMap json, String key)
      throws CodecException {
    JsonMap map = json.getMap(key);
    return (map == null) ? null : parse(map);
  }

  public static List<DescribableInt> parseList(JsonList json)
      throws CodecException {
    List<DescribableInt> ret = new ArrayList<>(json.size());
    for (JsonMap v : json.toMapList()) {
      ret.add(DescribableInt.parse(v));
    }
    return ret;
  }

} // class DescribableInt
