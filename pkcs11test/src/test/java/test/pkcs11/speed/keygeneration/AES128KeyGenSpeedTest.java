// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.speed.keygeneration;

/**
 * AES-128 speed test.
 *
 * @author Lijun Liao (xipki)
 */
public class AES128KeyGenSpeedTest extends AESKeyGenSpeedTest {

  @Override
  protected int getKeyByteLen() {
    return 16;
  }

}
