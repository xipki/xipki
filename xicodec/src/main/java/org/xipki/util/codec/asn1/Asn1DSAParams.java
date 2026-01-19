// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.codec.asn1;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.security.spec.InvalidKeySpecException;

/**
 * <pre>
 * DSA-Params ::= SEQUENCE {
 *   p  INTEGER,
 *   q  INTEGER,
 *   g  INTEGER
 *  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1DSAParams {

  private final byte[] p;

  private final byte[] q;

  private final byte[] g;

  public Asn1DSAParams(byte[] p, byte[] q, byte[] g) {
    this.p = Args.notNull(p, "p");
    this.q = Args.notNull(q, "q");
    this.g = Args.notNull(g, "g");
  }

  public byte[] getP() {
    return p;
  }

  public byte[] getQ() {
    return q;
  }

  public byte[] getG() {
    return g;
  }

  public static Asn1DSAParams getInstance(byte[] encoded)
      throws InvalidKeySpecException {
    try {
      byte[][] bns = Asn1Util.readBigInts(encoded, 3);
      int off = 1;
    return new Asn1DSAParams(bns[off++], bns[off++], bns[off]);
    } catch (CodecException e) {
      throw new InvalidKeySpecException(
          "invalid DSAParams: " + e.getMessage(), e);
    }
  }

}
