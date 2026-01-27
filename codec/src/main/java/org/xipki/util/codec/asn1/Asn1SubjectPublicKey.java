// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.codec.asn1;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * <pre>
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm            AlgorithmIdentifier,
 *      subjectPublicKey     BIT STRING  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1SubjectPublicKey {

  private final Asn1AlgorithmIdentifier algId;

  private final byte[] publicKeyData;

  public Asn1SubjectPublicKey(Asn1AlgorithmIdentifier algId,
                              byte[] publicKeyData) {
    this.algId = Args.notNull(algId, "algId");
    this.publicKeyData = Args.notNull(publicKeyData, "publicKeyData");
  }

  public Asn1AlgorithmIdentifier getAlgId() {
    return algId;
  }

  public byte[] getPublicKeyData() {
    return publicKeyData;
  }

  public static Asn1SubjectPublicKey getInstance(byte[] encoded)
      throws InvalidKeySpecException {
    String errMsg = "invalid SubjectPublicKey";
    AtomicInteger offset = new AtomicInteger();
    try {
      Asn1Util.readSeqPrefix(encoded, offset, errMsg);

      Asn1AlgorithmIdentifier algId = Asn1AlgorithmIdentifier.getInstance(
          encoded, offset);
      byte[] publicKeyData = Asn1Util.readOctetsFromASN1BitString(
          encoded, offset);
      return new Asn1SubjectPublicKey(algId, publicKeyData);
    } catch (CodecException e) {
      throw new InvalidKeySpecException(errMsg + ": " + e.getMessage(), e);
    }
  }

}
