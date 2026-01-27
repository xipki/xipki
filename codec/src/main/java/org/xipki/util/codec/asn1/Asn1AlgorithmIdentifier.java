// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.codec.asn1;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author Lijun Liao (xipki)
 */
public class Asn1AlgorithmIdentifier {

  private final String oid;

  private final byte[] params;

  public Asn1AlgorithmIdentifier(String oid, byte[] params) {
    this.oid = Args.notNull(oid, "oid");
    this.params = params;
  }

  public String getOid() {
    return oid;
  }

  public byte[] getParams() {
    return params;
  }

  public static Asn1AlgorithmIdentifier getInstance(byte[] encoded)
      throws InvalidKeySpecException {
    return getInstance(encoded, new AtomicInteger());
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof Asn1AlgorithmIdentifier)) {
      return false;
    }

    Asn1AlgorithmIdentifier b = (Asn1AlgorithmIdentifier) obj;
    if (!oid.equals(b.oid)) {
      return false;
    }

    if (params == null && b.params == null) {
      return true;
    }

    return Arrays.equals(params, b.params);
  }

  public static Asn1AlgorithmIdentifier getInstance(
      byte[] encoded, AtomicInteger offset)
      throws InvalidKeySpecException {
    String errMsg = "invalid AlgorithmIdentifier";
    try {
      int endIndex = Asn1Util.readSeqPrefix(encoded, offset, errMsg);
      String oid = Asn1Util.decodeOid(Asn1Util.readTLV(encoded, offset));

      byte[] algParams = null;
      if (offset.get() < endIndex) {
        algParams = Asn1Util.readTLV(encoded, offset);
      }

      return new Asn1AlgorithmIdentifier(oid, algParams);
    } catch (CodecException e) {
      throw new InvalidKeySpecException(errMsg + ": " + e.getMessage(), e);
    }
  }

}
