// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.codec.asn1;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * <pre>
 * OneAsymmetricKey ::= SEQUENCE {
 *   version                   Version,
 *   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
 *   privateKey                PrivateKey,
 *   attributes     IMPLICIT [0] Attributes OPTIONAL,
 *   ...,
 *   [[2: publicKey IMPLICIT [1] PublicKey OPTIONAL ]],
 *   ...
 * }
 *
 * PrivateKey ::= OCTET STRING
 * PublicKey  ::= BIT STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1OneAsymmetricKey {

  private final Asn1AlgorithmIdentifier privateKeyAlgorithm;

  private final byte[] privateKey;

  private final byte[] publicKey;

  public Asn1OneAsymmetricKey(Asn1AlgorithmIdentifier privateKeyAlgorithm,
                              byte[] privateKey, byte[] publicKey) {
    this.privateKeyAlgorithm = Args.notNull(privateKeyAlgorithm,
        "privateKeyAlgorithm");
    this.privateKey = Args.notNull(privateKey, "privateKey");
    this.publicKey = publicKey;
  }

  public Asn1AlgorithmIdentifier privateKeyAlgorithm() {
    return privateKeyAlgorithm;
  }

  public byte[] privateKey() {
    return privateKey;
  }

  public byte[] publicKey() {
    return publicKey;
  }

  public static Asn1OneAsymmetricKey getInstance(byte[] encoded)
      throws InvalidKeySpecException {
    String errMsg = "invalid OneAsymmetricKey";
    AtomicInteger offset = new AtomicInteger();

    try {
      int endIndex = Asn1Util.readSeqPrefix(encoded, offset, errMsg);

      // Version
      Asn1Util.skipCurrentTLV(encoded, offset);

      // privateKeyAlgorithm
      Asn1AlgorithmIdentifier privateKeyAlgorithm =
          Asn1AlgorithmIdentifier.getInstance(encoded, offset);

      byte[] privateKey =
          Asn1Util.readOctetsFromASN1OctetString(encoded, offset);

      byte[] publicKey = null;

      while (offset.get() < endIndex) {
        byte tag = encoded[offset.get()];
        if (tag == Asn1Const.TAG_IMPLICIT_ALT_1) {
          publicKey = Asn1Util.readValue(encoded, offset, true);
          break;
        } else {
          Asn1Util.skipCurrentTLV(encoded, offset);
        }
      }

      // ignore extra fields
      offset.set(endIndex);
      return new Asn1OneAsymmetricKey(privateKeyAlgorithm,
          privateKey, publicKey);
    } catch (CodecException e) {
      throw new InvalidKeySpecException(errMsg + ": " + e.getMessage(), e);
    }
  }

}
