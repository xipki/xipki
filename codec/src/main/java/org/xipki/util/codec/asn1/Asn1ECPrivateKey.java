// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.codec.asn1;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * <pre>
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey     OCTET STRING,
 *   parameters EXPLICIT [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  EXPLICIT [1] BIT STRING OPTIONAL
 * }
 *
 * @author Lijun Liao (xipki)
 * </pre>
 */
public class Asn1ECPrivateKey {

  private final byte[] privateKey;

  private final String namedCurve;

  private final byte[] publicKey;

  public Asn1ECPrivateKey(byte[] privateKey, String namedCurve,
                          byte[] publicKey) {
    this.privateKey = Args.notNull(privateKey, "privateKey");
    this.namedCurve = namedCurve;
    this.publicKey = publicKey;
  }

  public byte[] privateKey() {
    return privateKey;
  }

  public String namedCurve() {
    return namedCurve;
  }

  public byte[] publicKey() {
    return publicKey;
  }

  public static Asn1ECPrivateKey getInstance(byte[] encoded)
      throws InvalidKeySpecException {
    String errMsg = "invalid ECPrivateKey";
    AtomicInteger offset = new AtomicInteger();

    try {
      int endIndex = Asn1Util.readSeqPrefix(encoded, offset, errMsg);

      // Version
      Asn1Util.skipCurrentTLV(encoded, offset);

      // PrivateKey
      byte[] privateKey = Asn1Util.readOctetsFromASN1BitString(encoded, offset);

      // AlgorithmIdentifier
      Asn1AlgorithmIdentifier algId = Asn1AlgorithmIdentifier.getInstance(
          encoded, offset);
      byte[] publicKey = null;
      String namedCurve = null;

      while (offset.get() < endIndex) {
        byte tag = encoded[offset.get()];
        if (tag == Asn1Const.TAG_EXPLICIT_ALT_0) {
          namedCurve = Asn1Util.decodeOid(
              Asn1Util.readValue(encoded, offset)); // explicit
        } else if (tag == Asn1Const.TAG_EXPLICIT_ALT_1) {
          publicKey = Asn1Util.readValue(encoded, offset); // explicit
          break;
        } else {
          Asn1Util.skipCurrentTLV(encoded, offset);
        }
      }

      // ignore extra fields
      offset.set(endIndex);
      return new Asn1ECPrivateKey(privateKey, namedCurve, publicKey);
    } catch (CodecException e) {
      throw new InvalidKeySpecException(errMsg + ": " + e.getMessage(), e);
    }
  }

}
