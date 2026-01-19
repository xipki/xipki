// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class encapsulates parameters CK_LONG.
 *
 * @author Lijun Liao (xipki)
 */
public class LongParams extends CkParams {

  /**
   * The PKCS#11 object.
   */
  protected final long params;

  /**
   * Create a new LongParams object using the given object.
   *
   * @param params
   *          The params.
   */
  public LongParams(long params) {
    this.params = params;
  }

  public long params() {
    return params;
  }

  @Override
  public ParamsType type() {
    return ParamsType.LongParams;
  }

  @Override
  protected void addContent(EncodeList contents) {
    contents.v(params);
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return indent + "Long Params: " + params;
  }

  public static LongParams decode(Arch arch, byte[] encoded, AtomicInteger off)
      throws PKCS11Exception {
    assertType(encoded, off, ParamsType.LongParams);
    return new LongParams(readLong(arch, encoded, off));
  }

}
