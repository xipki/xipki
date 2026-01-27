// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.extn;

import org.xipki.ca.api.profile.id.ExtendedKeyUsageID;
import org.xipki.ca.certprofile.xijson.conf.extn.ExtendedKeyUsage;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableOid;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * Extension ExtendedKeyUsage.
 *
 * @author Lijun Liao (xipki)
 */

public class V1ExtendedKeyUsage {

  private final List<Usage> usages;

  private V1ExtendedKeyUsage(List<Usage> usages) {
    this.usages = Args.notEmpty(usages, "usages");
  }

  public ExtendedKeyUsage toV2() {
    List<ExtendedKeyUsageID> rList = new ArrayList<>(usages.size());
    List<ExtendedKeyUsageID> oList = new ArrayList<>(usages.size());
    for (Usage u : usages) {
      ExtendedKeyUsageID v2Id = ExtendedKeyUsageID.ofOid(u.oid());
      (u.isRequired() ? rList : oList).add(v2Id);
    }

    return new ExtendedKeyUsage(
        rList.isEmpty() ? null : rList,
        oList.isEmpty() ? null : oList);
  }

  public static V1ExtendedKeyUsage parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("usages");
    List<Usage> usages = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      usages.add(Usage.parse(v));
    }
    return new V1ExtendedKeyUsage((usages));
  }

  private static class Usage extends DescribableOid {

    private final boolean required;

    public Usage(String description, String oid, boolean required) {
      super(description, oid);
      this.required = required;
    }

    public boolean isRequired() {
      return required;
    }

    public static Usage parse(JsonMap json) throws CodecException {
      return new Usage(json.getString("description"),
          json.getNnString("oid"),
          json.getBool("required", false));
    }

  }

}
