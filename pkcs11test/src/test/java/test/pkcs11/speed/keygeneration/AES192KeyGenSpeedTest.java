// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.speed.keygeneration;

/**
 * AES-192 speed test.
 *
 * @author Lijun Liao (xipki)
 */
public class AES192KeyGenSpeedTest extends AESKeyGenSpeedTest {

  @Override
  protected int getKeyByteLen() {
    return 24;
  }

}
