// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.Backend;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.StoreSlotInfo;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.mgr.UserVerifier;
import org.xipki.pkcs11.xihsm.objects.XiP11Storage;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.util.codec.Args;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * @author Lijun Liao (xipki)
 */
public class MemPersistStore implements PersistStore {

  private static final Logger LOG = LoggerFactory.getLogger(
      MemPersistStore.class);

  private final StoreSlotInfo[] slotInfos;

  private final long[] slotIds;

  private final Map<Long, MemSlot> slots = new HashMap<>();

  public MemPersistStore(XiHsmVendor vendor) {
    Args.notNull(vendor, "vendor");
    final int numSlots = 2;
    this.slotIds = new long[numSlots];
    this.slotInfos = new StoreSlotInfo[numSlots];

    for (int i = 0; i < numSlots; i++) {
      final long slotId = 100 + i;
      this.slotIds[i] = slotId;
      MemSlot slot = new MemSlot(vendor, i, slotId);
      slotInfos[i] = slot.getSlotInfo();
      slots.put(slotId, slot);
    }
  }

  private MemSlot getSlot(long slotId) throws HsmException {
    return Optional.ofNullable(slots.get(slotId)).orElseThrow(
        () -> new HsmException(PKCS11T.CKR_SLOT_ID_INVALID,
              "invalid slotId " + slotId));
  }

  @Override
  public void addObject(long slotId, XiP11Storage object) throws HsmException {
    getSlot(slotId).addObject(object);
  }

  @Override
  public void findObjects(List<Long> res, long slotId, LoginState loginState,
                          XiTemplate criteria)
      throws HsmException {
    getSlot(slotId).findObjects(res, loginState, criteria);
  }

  @Override
  public XiP11Storage getObject(
      long slotId, long hObject, LoginState loginState) throws HsmException {
    return getSlot(slotId).getObject(hObject, loginState);
  }

  @Override
  public void updateObject(long slotId, long hObject, LoginState loginState,
                           XiTemplate attrs) throws HsmException {
    getSlot(slotId).updateObject(hObject, loginState, attrs);
  }

  @Override
  public void destroyObject(long slotId, long hObject, LoginState loginState)
      throws HsmException {
    getSlot(slotId).destroyObject(hObject, loginState);
  }

  @Override
  public long nextObjectHandle(long slotId) throws HsmException {
    return getSlot(slotId).nextObjectHandle();
  }

  @Override
  public long[] nextKeyPairHandles(long slotId) throws HsmException {
    return getSlot(slotId).nextObjectHandles(2);
  }

  @Override
  public StoreSlotInfo[] getSlotInfos() {
    return slotInfos.clone();
  }

  @Override
  public long[] getSlotIds() {
    return slotIds.clone();
  }

  @Override
  public void close() {
  }

  private static class MemSlot {

    private final ConcurrentHashMap<Long, XiP11Storage> handleObjectMap
        = new ConcurrentHashMap<>();

    private final XiHsmVendor vendor;
    private final StoreSlotInfo slotInfo;

    private final AtomicLong nextHandle = new AtomicLong(1);

    MemSlot(XiHsmVendor vendor, int slotIndex, long slotId) {
      this.vendor = vendor;
      this.slotInfo = new StoreSlotInfo(vendor, slotIndex, slotId,
          "1234", "mem slot 1234",
          NopUserVerifier.INSTANCE);
    }

    StoreSlotInfo getSlotInfo() {
      return slotInfo;
    }

    void addObject(XiP11Storage object) throws HsmException {
      long hObject = object.getHandle();
      if (handleObjectMap.containsKey(hObject)) {
        throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
            "could not add object: hObject " + hObject +
                " in slot " + slotInfo.getSlotId());
      }
      XiP11Storage newObj = XiP11Storage.decode(
          vendor, hObject, object.encode());

      handleObjectMap.put(hObject, newObj);
      LOG.debug("added object {} in slot {}", hObject, slotInfo.getSlotId());
    }

    void findObjects(List<Long> res, LoginState loginState,
                     XiTemplate criteria) {
      for (Map.Entry<Long, XiP11Storage> kv : handleObjectMap.entrySet()) {
        XiP11Storage obj = kv.getValue();
        if (obj.isVisibleForCku(loginState) && obj.match(criteria)) {
          res.add(kv.getKey());
        }
      }
    }

    XiP11Storage getObject(long hObject, LoginState loginState)
        throws HsmException {
      XiP11Storage ret = handleObjectMap.get(hObject);
      if (ret == null) {
        throw new HsmException(PKCS11T.CKR_OBJECT_HANDLE_INVALID,
            "found no object for hObject " + hObject);
      }

      if (!ret.isVisibleForCku(loginState)) {
        throw new HsmException(PKCS11T.CKR_OBJECT_HANDLE_INVALID,
            "object is not visible");
      }
      return ret;
    }

    void updateObject(long hObject, LoginState loginState, XiTemplate attrs)
      throws HsmException {
      XiP11Storage obj = getObject(hObject, loginState);
      obj.updateAttributes(loginState, ObjectInitMethod.UPDATE, attrs);

      XiP11Storage newObj = XiP11Storage.decode(vendor, hObject, obj.encode());
      handleObjectMap.put(hObject, newObj);
      LOG.debug("updated object {} in slot {}", hObject, slotInfo.getSlotId());
    }

    void destroyObject(long hObject, LoginState loginState)
        throws HsmException {
      XiP11Storage obj = getObject(hObject, loginState);

      if (!obj.isDestroyable()) {
        throw new HsmException(PKCS11T.CKR_ACTION_PROHIBITED,
            "object is not destroyable");
      }

      handleObjectMap.remove(obj.getHandle());
      LOG.debug("deleted object {} in slot {}", hObject, slotInfo.getSlotId());
    }

    public synchronized long[] nextObjectHandles(int num) throws HsmException {
      Args.range(num, "num", 1, 100);

      long[] ret = new long[num];
      int tries = 0;
      for (int i = 0; i < num; i++) {
        long cHandle = -1;
        while (tries < Backend.MAX_TOKEN_HANDLE) {
          tries++;
          long handle = nextHandle.getAndIncrement();
          if (nextHandle.get() > Backend.MAX_TOKEN_HANDLE) {
            LOG.warn("nextHandle reached end, reset it to 1");
            nextHandle.set(1L);
          }

          if (isHandleFree(handle)) {
            cHandle = handle;
            break;
          }
        }

        if (cHandle == -1) {
          throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
              "no available handle");
        }

        ret[i] = cHandle;
      }

      return ret;
    }

    public long nextObjectHandle() throws HsmException {
      return nextObjectHandles(1)[0];
    }

    private boolean isHandleFree(long hObject) {
      return !handleObjectMap.containsKey(hObject);
    }

  }

  private static class NopUserVerifier implements UserVerifier {

    private static final NopUserVerifier INSTANCE = new NopUserVerifier();

    @Override
    public void verify(long userType, byte[] pin) throws HsmException {
    }
  }

}
