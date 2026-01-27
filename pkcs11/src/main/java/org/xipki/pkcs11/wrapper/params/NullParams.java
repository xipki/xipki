// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Mechanism parameter of value NULL.
 * @author Lijun Liao (xipki)
 */
public class NullParams extends CkParams {

  public static final NullParams INSTANCE = new NullParams();

  private NullParams() {
  }

  @Override
  public ParamsType type() {
    return ParamsType.NullParams;
  }

  @Override
  protected void addContent(EncodeList contents) {
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return indent + "<NULL>";
  }

  public static NullParams decode(byte[] encoded, AtomicInteger off)
      throws PKCS11Exception {
    assertType(encoded, off, ParamsType.NullParams);
    return INSTANCE;
  }

}
