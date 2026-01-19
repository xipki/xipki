// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.mgr;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

import java.util.ArrayList;
import java.util.List;

/**
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

  public void encodeTo(CborEncoder encoder) throws HsmException {
    try {
      encoder.writeArrayStart(users.size());
      for (User user : users) {
        user.encodeTo(encoder);
      }
    } catch (CodecException e) {
      throw HsmException.newGeneralError("error encoding SlotUsers", e);
    }
  }

  public static SlotUsers decode(CborDecoder decoder) throws HsmException {
    try {
      int size = decoder.readArrayLength();
      List<User> users = new ArrayList<>(size);
      for (int i = 0; i < size; i++) {
        users.add(User.decode(decoder));
      }
      return new SlotUsers(users);
    } catch (CodecException e) {
      throw HsmException.newGeneralError("error encoding User", e);
    }
  }

}
