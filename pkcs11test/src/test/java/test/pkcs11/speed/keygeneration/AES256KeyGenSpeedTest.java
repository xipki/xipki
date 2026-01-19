// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.speed.keygeneration;

/**
 * AES-256 speed test.
 *
 * @author Lijun Liao (xipki)
 */
public class AES256KeyGenSpeedTest extends AESKeyGenSpeedTest {

  @Override
  protected int getKeyByteLen() {
    return 32;
  }

}
