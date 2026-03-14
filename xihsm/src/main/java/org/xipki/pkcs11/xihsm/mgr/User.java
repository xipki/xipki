// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.mgr;

import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.Hex;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

import java.util.Arrays;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class User implements JsonEncodable {

  private final long userType;

  private final byte[] pin;

  public User(long userType, byte[] pin) {
    this.userType = userType;
    this.pin = pin;
  }

  public long getUserType() {
    return userType;
  }

  public void verify(byte[] pin) throws HsmException {
    if (!Arrays.equals(this.pin, pin)) {
      throw new HsmException(PKCS11T.CKR_PIN_INCORRECT, "PIN incorrect");
    }
  }

  @Override
  public JsonMap toCodec() {
    JsonMap map = new JsonMap();
    map.put("userType", PKCS11T.ckuCodeToName(userType));
    map.put("pin", Hex.encode(pin));
    return map;
  }

  public static User decode(JsonMap jMap) throws HsmException {
    try {
      long userType = PKCS11T.nonnullNameToCode(Category.CKU, jMap.getNnString("userType"));
      byte[] pin = Hex.decode(jMap.getNnString("pin"));
      return new User(userType, pin);
    } catch (CodecException e) {
      throw HsmException.newGeneralError("error encoding User", e);
    }
  }

}
