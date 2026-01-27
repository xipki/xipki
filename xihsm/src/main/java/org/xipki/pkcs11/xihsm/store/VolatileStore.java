// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.Backend;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.objects.XiP11Storage;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * @author Lijun Liao (xipki)
 */
public class VolatileStore implements Store {

  private static final Logger LOG =
      LoggerFactory.getLogger(VolatileStore.class);

  private final HashMap<Long, Slot> slotsMap = new HashMap<>();

  public VolatileStore(long[] slotIds) {
    for (long slotId : slotIds) {
      slotsMap.put(slotId, new Slot(slotId));
    }
  }

  @Override
  public void addObject(long slotId, XiP11Storage object) throws HsmException {
    getSlot(slotId).addObject(object);
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
  public long[] nextKeyPairHandles(long slotId)
      throws HsmException {
    Slot slot = getSlot(slotId);
    return new long[] {
        slot.nextObjectHandle(), slot.nextObjectHandle()};
  }

  @Override
  public void close() {
  }

  public void destroyAllObjects(long slotId) throws HsmException {
    getSlot(slotId).destroyAllObjects();
  }

  @Override
  public void findObjects(List<Long> res, long slotId, LoginState loginState,
                          XiTemplate criteria)
      throws HsmException {
    getSlot(slotId).findObjects(res, loginState, criteria);
  }

  public void setAttributeValue(
      long slotId, long hObject, LoginState loginState, XiTemplate attributes)
      throws HsmException {
    getSlot(slotId).setAttributeValues(hObject, loginState, attributes);
  }

  @Override
  public XiP11Storage getObject(
      long slotId, long hObject, LoginState loginState) throws HsmException {
    return getSlot(slotId).getObject(hObject, loginState);
  }

  private Slot getSlot(long slotId) throws HsmException {
    return Optional.ofNullable(slotsMap.get(slotId)).orElseThrow(
        () -> new HsmException(PKCS11T.CKR_SLOT_ID_INVALID,
              "invalid slot id " + slotId));
  }

  @Override
  public void updateObject(
      long slotId, long hObject, LoginState loginState, XiTemplate attrs)
      throws HsmException {
    getSlot(slotId).setAttributeValues(hObject, loginState, attrs);
  }

  private static class Slot {

    private final long slotId;

    private final Map<Long, XiP11Storage> handleObjectMap =
        new ConcurrentHashMap<>();

    private final AtomicLong nextHandle =
        new AtomicLong(Backend.MIN_VOLATILE_HANDLE);

    public Slot(long slotId) {
      this.slotId = slotId;
    }

    void addObject(XiP11Storage object) throws HsmException {
      long handle = object.getHandle();
      if (handleObjectMap.containsKey(handle)) {
        throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
            "could not add object since the handle is occupied");
      }

      handleObjectMap.put(handle, object);
    }

    void findObjects(List<Long> res, LoginState loginState,
                     XiTemplate criteria) {
      for (Map.Entry<Long, XiP11Storage> kv : handleObjectMap.entrySet()) {
        if (kv.getValue().match(criteria)) {
          if (kv.getValue().isVisibleForCku(loginState)) {
            res.add(kv.getKey());
          }
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
            "object " + hObject + "is not visible");
      }

      return ret;
    }

    void destroyObject(long hObject, LoginState loginState)
        throws HsmException {
      XiP11Storage obj = getObject(hObject, loginState);
      if (!obj.isDestroyable()) {
        throw new HsmException(PKCS11T.CKR_ACTION_PROHIBITED,
            "object is not destroyable");
      }

      handleObjectMap.remove(obj.getHandle());
      LOG.debug("deleted volatile object {} in slot {}", hObject, slotId);
    }

    void destroyAllObjects() {
      handleObjectMap.clear();
    }

    void setAttributeValues(long hObject, LoginState loginState,
                            XiTemplate attributes) throws HsmException {
      getObject(hObject, loginState).updateAttributes(loginState,
          ObjectInitMethod.UPDATE, attributes);
    }

    long nextObjectHandle() throws HsmException {
      synchronized (nextHandle) {
        for (int i = 0; i < 1_000_000; i++) {
          long handle = nextHandle.getAndIncrement();
          if (nextHandle.get() > Backend.MAX_VOLATILE_HANDLE) {
            nextHandle.set(Backend.MIN_VOLATILE_HANDLE);
            LOG.warn("nextObjectHandle for volatile objects reached end," +
                "reset it to {}", Backend.MIN_VOLATILE_HANDLE);
          }

          if (!handleObjectMap.containsKey(handle)) {
            return handle;
          }
        }

        throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
            "could not get free handle for volatile object in slot " + slotId);
      }
    }
  }

}
