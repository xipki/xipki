// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.type;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

/**
 * Binary with description.
 *
 * @author Lijun Liao (xipki)
 */
public class DescribableBinary extends V1Describable {

  private final byte[] value;

  public DescribableBinary(String description, byte[] value) {
    super(description);
    this.value = Args.notNull(value, "value");
  }

  public byte[] value() {
    return value;
  }

  public static DescribableBinary parse(JsonMap json) throws CodecException {
    return new DescribableBinary(json.getString("description"),
        json.getNnBytes("value"));
  }

  public static DescribableBinary parseNn(JsonMap json, String key)
      throws CodecException {
    DescribableBinary v = parse(json, key);
    if (v == null) {
      throw new CodecException(key + " is not present");
    }
    return v;
  }

  public static DescribableBinary parse(JsonMap json, String key)
      throws CodecException {
    JsonMap map = json.getMap(key);
    return (map == null) ? null : parse(map);
  }

} // class DescribableBinary
