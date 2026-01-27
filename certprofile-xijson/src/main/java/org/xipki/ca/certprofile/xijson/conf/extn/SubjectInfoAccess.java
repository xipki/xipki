// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.ca.api.profile.id.AccessMethodID;
import org.xipki.ca.certprofile.xijson.conf.GeneralNameType;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * Extension SubjectInfoAccess.
 *
 * @author Lijun Liao (xipki)
 */

public class SubjectInfoAccess implements JsonEncodable {

  private final List<Access> accesses;

  public SubjectInfoAccess(List<Access> accesses) {
    this.accesses = Args.notEmpty(accesses, "accesses");
  }

  public List<Access> getAccesses() {
    return accesses;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEncodables("accesses", accesses);
  }

  public static SubjectInfoAccess parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("accesses");
    List<Access> accesses = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      accesses.add(Access.parse(v));
    }
    return new SubjectInfoAccess(accesses);
  }

  public static class Access implements JsonEncodable {

    private final AccessMethodID accessMethod;

    private final GeneralNameType accessLocation;

    public Access(AccessMethodID accessMethod, GeneralNameType accessLocation) {
      this.accessMethod = Args.notNull(accessMethod, "accessMethod");
      this.accessLocation = Args.notNull(accessLocation, "accessLocation");
    }

    public AccessMethodID getAccessMethod() {
      return accessMethod;
    }

    public GeneralNameType getAccessLocation() {
      return accessLocation;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap()
          .put("accessMethod", accessMethod.getMainAlias())
          .put("accessLocation", accessLocation);
    }

    public static Access parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("accessLocation");
      GeneralNameType accessLocation = (map == null) ? null
          : GeneralNameType.parse(map);
      return new Access(
          AccessMethodID.ofOidOrName(json.getNnString("accessMethod")),
          accessLocation);
    }

  }

}
