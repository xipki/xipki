/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security;

/**
 * Algorithm code. Defined intern in XiPKI.
 *
 * @author Lijun Liao
 * @since 2.2.0
 */

public enum AlgorithmCode {
  // RSA PKCS1v1_5
  SHA1WITHRSA((byte) 0x01),
  SHA224WITHRSA((byte) 0x02),
  SHA256WITHRSA((byte) 0x03),
  SHA384WITHRSA((byte) 0x04),
  SHA512WITHRSA((byte) 0x05),
  SHA3_224WITHRSA((byte) 0x06),
  SHA3_256WITHRSA((byte) 0x07),
  SHA3_384WITHRSA((byte) 0x08),
  SHA3_512WITHRSA((byte) 0x09),

  // RSA and MGF1
  SHA1WITHRSAANDMGF1((byte) 0x11),
  SHA224WITHRSAANDMGF1((byte) 0x12),
  SHA256WITHRSAANDMGF1((byte) 0x13),
  SHA384WITHRSAANDMGF1((byte) 0x14),
  SHA512WITHRSAANDMGF1((byte) 0x15),
  SHA3_224WITHRSAANDMGF1((byte) 0x16),
  SHA3_256WITHRSAANDMGF1((byte) 0x17),
  SHA3_384WITHRSAANDMGF1((byte) 0x18),
  SHA3_512WITHRSAANDMGF1((byte) 0x19),
  SHAKE128WITHRSAPSS((byte) 0x1A),
  SHAKE256WITHRSAPSS((byte) 0x1B),

  // DSA
  SHA1WITHDSA((byte) 0x21),
  SHA224WITHDSA((byte) 0x22),
  SHA256WITHDSA((byte) 0x23),
  SHA384WITHDSA((byte) 0x24),
  SHA512WITHDSA((byte) 0x25),
  SHA3_224WITHDSA((byte) 0x26),
  SHA3_256WITHDSA((byte) 0x27),
  SHA3_384WITHDSA((byte) 0x28),
  SHA3_512WITHDSA((byte) 0x29),

  // ECDSA
  SHA1WITHECDSA((byte) 0x31),
  SHA224WITHECDSA((byte) 0x32),
  SHA256WITHECDSA((byte) 0x33),
  SHA384WITHECDSA((byte) 0x34),
  SHA512WITHECDSA((byte) 0x35),
  SHA3_224WITHECDSA((byte) 0x36),
  SHA3_256WITHECDSA((byte) 0x37),
  SHA3_384WITHECDSA((byte) 0x38),
  SHA3_512WITHECDSA((byte) 0x39),
  SM2WITHSM3((byte) 0x3A),
  SHAKE128WITHECDSA((byte) 0x3B),
  SHAKE256WITHECDSA((byte) 0x3C),

  // PlainECDSA
  SHA1WITHPLAIN_ECDSA((byte) 0x41),
  SHA224WITHPLAIN_ECDSA((byte) 0x42),
  SHA256WITHPLAIN_ECDSA((byte) 0x43),
  SHA384WITHPLAIN_ECDSA((byte) 0x44),
  SHA512WITHPLAIN_ECDSA((byte) 0x45),

  // EdDSA
  ED25519((byte) 0x46),
  ED448((byte) 0x47),

  // HMAC
  HMAC_SHA1((byte) 0x51),
  HMAC_SHA224((byte) 0x52),
  HMAC_SHA256((byte) 0x53),
  HMAC_SHA384((byte) 0x54),
  HMAC_SHA512((byte) 0x55),
  HMAC_SHA3_224((byte) 0x56),
  HMAC_SHA3_256((byte) 0x57),
  HMAC_SHA3_384((byte) 0x58),
  HMAC_SHA3_512((byte) 0x59),

  // DHPOC-MAC
  DHPOP_X25519_SHA256((byte) 0x5a),
  DHPOP_X448_SHA512((byte) 0x5b),

  // AES-GMAC
  AES128_GMAC((byte) 0x61),
  AES192_GMAC((byte) 0x62),
  AES256_GMAC((byte) 0x63),

  // Hash Algorithm
  SHA1((byte) 0xE1),
  SHA224((byte) 0xE2),
  SHA256((byte) 0xE3),
  SHA384((byte) 0xE4),
  SHA512((byte) 0xE5),
  SHA3_224((byte) 0xE6),
  SHA3_256((byte) 0xE7),
  SHA3_384((byte) 0xE8),
  SHA3_512((byte) 0xE9),
  SM3((byte) 0xEA),
  SHAKE128((byte) 0xEB),
  SHAKE256((byte) 0xEC);

  private byte code;

  private AlgorithmCode(byte code) {
    this.code = code;
  }

  public byte getCode() {
    return code;
  }

}
