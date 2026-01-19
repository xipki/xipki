// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.util;

import org.bouncycastle.util.encoders.Hex;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.type.CkVersion;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.asn1.Asn1Util;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class HsmUtil {

  private static final SecureRandom rnd = new SecureRandom();

  public static long[] listToLongs(List<Long> list) {
    long[] ret = new long[list.size()];
    int i = 0;
    for (long l : list) {
      ret[i++] = l;
    }
    return ret;
  }

  public static byte[] randomBytes(int size) {
    byte[] bytes = new byte[size];
    rnd.nextBytes(bytes);
    return bytes;
  }

  public static CkVersion buildVersion(int major, int minor) {
    return new CkVersion((byte) major, (byte) minor);
  }

  public static long[] concatenate(long[] list, long... newElements) {
    long[] newList = Arrays.copyOf(list, list.length + newElements.length);
    System.arraycopy(newElements, 0, newList, list.length, newElements.length);
    return newList;
  }

  public static boolean contains(long[] list, long element) {
    for (long i : list) {
      if (i == element) {
        return true;
      }
    }
    return false;
  }

  public static void assertNullParameter(XiMechanism mechanism)
      throws HsmException {
    if (mechanism.getParameter() != null) {
      throw new HsmException(PKCS11T.CKR_MECHANISM_PARAM_INVALID,
          "Mechanism.parameters is not NULL");
    }
  }

  public static byte[] getOctetStringValue(String name, byte[] derOctetString)
      throws HsmException {
    try {
      return Asn1Util.readOctetsFromASN1OctetString(derOctetString);
    } catch (CodecException e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          name + " is not a DER-encoded OCTET STRING: "
           + Hex.toHexString(derOctetString));
    }
  }

}
