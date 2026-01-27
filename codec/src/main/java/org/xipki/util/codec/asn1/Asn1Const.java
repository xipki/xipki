// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.codec.asn1;

/**
 * @author Lijun Liao (xipki)
 */
public class Asn1Const {

  public static final String id_ecPublicKey = "1.2.840.10045.2.1";

  public static final String id_rsaPublicKey = "1.2.840.113549.1.1.1";

  public static final String id_dsaPublicKey = "1.2.840.10040.4.1";

  public static final String id_x25519 = "1.3.101.110";

  public static final String id_x448 = "1.3.101.111";

  public static final String id_ed25519 = "1.3.101.112";

  public static final String id_ed448 = "1.3.101.113";

  public static final String id_sm2p256v1 = "1.2.156.10197.1.301";

  public static final String id_mldsa44   = "2.16.840.1.101.3.4.3.17";

  public static final String id_mldsa65   = "2.16.840.1.101.3.4.3.18";

  public static final String id_mldsa87   = "2.16.840.1.101.3.4.3.19";

  public static final String id_mlkem512  = "2.16.840.1.101.3.4.4.1";

  public static final String id_mlkem768  = "2.16.840.1.101.3.4.4.2";

  public static final String id_mlkem1024 = "2.16.840.1.101.3.4.4.3";

  public static final byte TAG_SEQUENCE = 0x30;

  public static final byte TAG_SET = 0x31;

  public static final byte TAG_INTEGER = 0x02;

  public static final byte TAG_BIT_STRING = 0x03;

  public static final byte TAG_OCTET_STRING = 0x04;

  public static final byte TAG_OID = 0x06;

  public static final byte TAG_UTF8_STRING = 0x0C;

  public static final byte TAG_PRINTABLE_STRING = 0x13;

  public static final byte TAG_IMPLICIT_ALT_0 = (byte) 0x80;

  public static final byte TAG_IMPLICIT_ALT_1 = (byte) 0x81;

  public static final byte TAG_EXPLICIT_ALT_0 = (byte) 0xA0;

  public static final byte TAG_EXPLICIT_ALT_1 = (byte) 0xA1;

}
