// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.mgr;

import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.ByteArrayCborDecoder;
import org.xipki.util.codec.cbor.ByteArrayCborEncoder;
import org.xipki.util.codec.cbor.CborDecoder;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
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
    try (ByteArrayCborEncoder encoder = new ByteArrayCborEncoder()) {
      encoder.writeArrayStart(2);
      encoder.writeInt(1); // version

      encoder.writeMapStart(slotUsersMap.size());
      for (Map.Entry<Long, SlotUsers> kv : slotUsersMap.entrySet()) {
        encoder.writeLong(kv.getKey());
        kv.getValue().encodeTo(encoder);
      }
      return encoder.toByteArray();
    } catch (CodecException | IOException e) {
      throw HsmException.newGeneralError("error encoding TenantInfo", e);
    }
  }

  public static TenantInfo decode(byte[] encoded) throws HsmException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      decoder.readArrayLength(2);
      int version = decoder.readInt();
      if (version != 1) {
        throw HsmException.newGeneralError("unknown version " + version);
      }

      int size = decoder.readMapLength();
      Map<Long, SlotUsers> slotUsersMap = new HashMap<>(size);
      for (int i = 0; i < size; i++) {
        long slotId = decoder.readLong();
        slotUsersMap.put(slotId, SlotUsers.decode(decoder));
      }
      return new TenantInfo(slotUsersMap);
    } catch (CodecException e) {
      throw HsmException.newGeneralError("error decoding TenantInfo", e);
    }
  }

}
