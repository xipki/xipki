// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Collection of OBJECT IDENTIFIERS.
 *
 * @author Lijun Liao (xipki)
 */

public class OIDs {

  public static final ASN1ObjectIdentifier x25519 =
      new ASN1ObjectIdentifier("1.3.101.110");

  public static final ASN1ObjectIdentifier x448 =
      new ASN1ObjectIdentifier("1.3.101.111");

  public static final ASN1ObjectIdentifier ed25519 =
      new ASN1ObjectIdentifier("1.3.101.112");

  public static final ASN1ObjectIdentifier ed448 =
      new ASN1ObjectIdentifier("1.3.101.113");

  public static final ASN1ObjectIdentifier sm2p256v1 =
      new ASN1ObjectIdentifier("1.2.156.10197.1.301");

  public static final ASN1ObjectIdentifier frp256v1 =
      new ASN1ObjectIdentifier("1.2.250.1.223.101.256.1");

  public static final ASN1ObjectIdentifier secp256r1 =
      new ASN1ObjectIdentifier("1.2.840.10045.3.1.7");

  public static final ASN1ObjectIdentifier secp384r1 =
      new ASN1ObjectIdentifier("1.3.132.0.34");

  public static final ASN1ObjectIdentifier secp521r1 =
      new ASN1ObjectIdentifier("1.3.132.0.35");

  public static final ASN1ObjectIdentifier brainpoolP256r1 =
      new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.7");

  public static final ASN1ObjectIdentifier brainpoolP384r1 =
      new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.11");

  public static final ASN1ObjectIdentifier brainpoolP512r1 =
      new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.13");

}
