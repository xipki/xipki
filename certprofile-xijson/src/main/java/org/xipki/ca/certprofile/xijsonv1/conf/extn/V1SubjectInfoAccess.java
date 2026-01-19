// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.extn;

import org.xipki.ca.api.profile.id.AccessMethodID;
import org.xipki.ca.certprofile.xijson.conf.extn.SubjectInfoAccess;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableOid;
import org.xipki.ca.certprofile.xijsonv1.conf.type.V1GeneralNameType;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * Extension SubjectInfoAccess.
 *
 * @author Lijun Liao (xipki)
 */

public class V1SubjectInfoAccess {

  private final List<Access> accesses;

  private V1SubjectInfoAccess(List<Access> accesses) {
    this.accesses = Args.notEmpty(accesses, "accesses");
  }

  public SubjectInfoAccess toV2() {
    List<SubjectInfoAccess.Access> list = new ArrayList<>(accesses.size());
    for (Access access : accesses) {
      list.add(access.toV2());
    }

    return new SubjectInfoAccess(list);
  }

  public static V1SubjectInfoAccess parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("accesses");
    List<Access> accesses = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      accesses.add(Access.parse(v));
    }
    return new V1SubjectInfoAccess(accesses);
  }

  private static class Access {

    private final DescribableOid accessMethod;

    private final V1GeneralNameType accessLocation;

    public Access(DescribableOid accessMethod,
                  V1GeneralNameType accessLocation) {
      this.accessMethod = Args.notNull(accessMethod, "accessMethod");
      this.accessLocation = Args.notNull(accessLocation, "accessLocation");
    }

    public SubjectInfoAccess.Access toV2() {
      return new SubjectInfoAccess.Access(
          AccessMethodID.ofOid(accessMethod.oid()), accessLocation.toV2());
    }

    public static Access parse(JsonMap json) throws CodecException {
      return new Access(
          DescribableOid.parseNn(json, "accessMethod"),
          V1GeneralNameType.parse(json.getNnMap("accessLocation")));
    }

  }

}
