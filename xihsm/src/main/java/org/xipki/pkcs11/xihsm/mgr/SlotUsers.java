// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.mgr;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class SlotUsers implements UserVerifier {

  private final List<User> users;

  public SlotUsers(List<User> users) {
    this.users = Args.notNull(users, "users");
  }

  @Override
  public void verify(long userType, byte[] pin) throws HsmException {
    for (User user : users) {
      if (user.getUserType() == userType) {
        user.verify(pin);
        return;
      }
    }

    throw new HsmException(PKCS11T.CKR_USER_TYPE_INVALID,
        "invalid user type " + PKCS11T.ckuCodeToName(userType));
  }

  public JsonList toCodec() throws HsmException {
    try {
      JsonList list = new JsonList();
      for (User user : users) {
        list.add(user.toCodec());
      }
      return list;
    } catch (RuntimeException e) {
      throw HsmException.newGeneralError("error encoding SlotUsers", e);
    }
  }

  public static SlotUsers decode(JsonList jList) throws HsmException {
    try {
      int size = jList.size();
      List<User> users = new ArrayList<>(size);
      List<JsonMap> list2 = jList.toMapList();
      for (int i = 0; i < size; i++) {
        users.add(User.decode(list2.get(i)));
      }
      return new SlotUsers(users);
    } catch (CodecException e) {
      throw HsmException.newGeneralError("error encoding User", e);
    }
  }

}
