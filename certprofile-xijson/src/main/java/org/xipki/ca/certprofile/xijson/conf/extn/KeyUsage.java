// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.ca.certprofile.xijson.KeyUsageControl;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * Extension KeyUsage.
 *
 * @author Lijun Liao (xipki)
 */

public class KeyUsage implements JsonEncodable {

  private final List<SingleKeyUsages> usages;

  public KeyUsage(List<SingleKeyUsages> usages) {
    this.usages = Args.notEmpty(usages, "usages");
  }

  public List<SingleKeyUsages> getUsages() {
    return usages;
  }

  public KeyUsageControl toXiKeyUsageOptions() {
    List<KeyUsageControl.KeySingleUsages> singleUsagesList
        = new ArrayList<>(usages.size());
    for (SingleKeyUsages x : usages) {
      singleUsagesList.add(x.toXiKeyUsageOptions());
    }
    return new KeyUsageControl(singleUsagesList);
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEncodables("usages", usages);
  }

  public static KeyUsage parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("usages");
    List<SingleKeyUsages> usagesList = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      usagesList.add(SingleKeyUsages.parse(v));
    }
    return new KeyUsage(usagesList);
  }

}
