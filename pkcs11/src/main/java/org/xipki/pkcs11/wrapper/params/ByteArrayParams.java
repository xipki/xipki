// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.util.codec.Args;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class encapsulates parameters byte arrays.
 *
 * @author Lijun Liao (xipki)
 */
public class ByteArrayParams extends CkParams {

  private final byte[] bytes;

  public ByteArrayParams(byte[] bytes) {
    this.bytes = Args.notNull(bytes, "bytes");
  }

  public byte[] bytes() {
    return bytes;
  }

  @Override
  public ParamsType type() {
    return ParamsType.ByteArrayParams;
  }

  @Override
  protected void addContent(EncodeList contents) {
    contents.v(bytes);
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return  indent + "ByteArray Params:\n"
        + Functions.toString(indent + "  ", bytes);
  }

  public static ByteArrayParams decode(
      Arch arch, byte[] encoded, AtomicInteger off)
      throws PKCS11Exception {
    assertType(encoded, off, ParamsType.ByteArrayParams);
    return new ByteArrayParams(readByteArray(arch, encoded, off));
  }

}
