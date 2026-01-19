// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.test;

import org.xipki.util.codec.Base64;

/**
 * Test for {@link Base64} with standard Base64 letters.
 *
 * @author Lijun Liao (xipki)
 */
public class Base64Test extends AbstractBase64Test {

  @Override
  protected String jdkEncode(byte[] data) {
    return java.util.Base64.getEncoder().encodeToString(data);
  }

  private static Base64.Encoder getEncoder(boolean withPadding) {
    return withPadding ? Base64.getEncoder() : Base64.getNoPaddingEncoder();
  }

  @Override
  protected byte[] encodeToByte(byte[] data, boolean wrapLongLine,
                                boolean withPadding) {
    return getEncoder(withPadding).encodeToByte(data, wrapLongLine);
  }

  @Override
  protected String encodeToString(byte[] data, boolean wrapLongLine,
                                  boolean withPadding) {
    return getEncoder(withPadding).encodeToString(data, wrapLongLine);
  }

  @Override
  protected byte[] decode(byte[] data) {
    return Base64.decode(data);
  }

  @Override
  protected byte[] decode(String data) {
    return Base64.decode(data);
  }

  @Override
  protected byte[] decodeFast(byte[] data) {
    return Base64.decodeFast(data);
  }

  @Override
  protected byte[] decodeFast(String data) {
    return Base64.decodeFast(data);
  }
}
