// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.mgr;

import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class TenantInfo {

  private final Map<Long, SlotUsers> slotUsersMap;

  public TenantInfo(Map<Long, SlotUsers> slotUsersMap) {
    this.slotUsersMap = slotUsersMap;
  }

  public SlotUsers getSlotUsers(long slotId) {
    return slotUsersMap.get(slotId);
  }

  public byte[] encode() throws HsmException {
    JsonMap map = new JsonMap();
    map.put("version", 1);

    JsonList jSlotUsersMapList = new JsonList();
    for (Map.Entry<Long, SlotUsers> kv : slotUsersMap.entrySet()) {
      JsonMap subMap = new JsonMap();
      subMap.put("slotId", kv.getKey());
      subMap.put("users", kv.getValue().toCodec());
      jSlotUsersMapList.add(subMap);
    }

    map.put("slots", jSlotUsersMapList);

    try {
      return JsonBuilder.toPrettyJson(map).getBytes(StandardCharsets.UTF_8);
    } catch (RuntimeException e) {
      throw HsmException.newGeneralError("error encoding TenantInfo", e);
    }
  }

  public static TenantInfo decode(byte[] encoded) throws HsmException {
    try {
      JsonMap jMap = JsonParser.parseMap(encoded, false);
      int version = jMap.getInt("version");
      if (version != 1) {
        throw HsmException.newGeneralError("unknown version " + version);
      }

      List<JsonMap> jList = jMap.getNnList("slots").toMapList();
      int size = jList.size();
      Map<Long, SlotUsers> slotUsersMap = new HashMap<>(size);
      for (JsonMap m : jList) {
        long slotId = m.getNnLong("slotId");
        SlotUsers slotUsers = SlotUsers.decode(m.getNnList("users"));
        slotUsersMap.put(slotId, slotUsers);
      }
      return new TenantInfo(slotUsersMap);
    } catch (CodecException e) {
      throw HsmException.newGeneralError("error decoding TenantInfo", e);
    }
  }

}
