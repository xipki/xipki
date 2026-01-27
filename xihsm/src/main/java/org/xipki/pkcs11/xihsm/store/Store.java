// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.store;

import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.objects.XiP11Storage;
import org.xipki.pkcs11.xihsm.util.HsmException;

import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public interface Store {

  void addObject(long slotId, XiP11Storage object) throws HsmException;

  void findObjects(List<Long> res, long slotId, LoginState loginState,
                   XiTemplate criteria)
      throws HsmException;

  XiP11Storage getObject(long slotId, long hObject, LoginState loginState)
      throws HsmException;

  void updateObject(long slotId, long hObject, LoginState loginState,
                    XiTemplate attrs) throws HsmException;

  void destroyObject(long slotId, long hObject, LoginState loginState)
      throws HsmException;

  long nextObjectHandle(long slotId) throws HsmException;

  long[] nextKeyPairHandles(long slotId) throws HsmException;

  void close();

}
