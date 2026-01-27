// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * RFC 3779, 8360
 * <pre>
 * IPAddrBlocks        ::= SEQUENCE OF IPAddressFamily
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IPAddrBlocks extends ASN1Object {

  private final List<ASN1IPAddressFamily> blocks;

  public IPAddrBlocks(List<ASN1IPAddressFamily> blocks) {
    this.blocks = Args.notNull(blocks, "blocks");
  }

  private IPAddrBlocks(ASN1Sequence seq) {
    this.blocks = new ArrayList<>(seq.size());
    for (int i = 0; i < seq.size(); i++) {
      this.blocks.add(ASN1IPAddressFamily.getInstance(seq.getObjectAt(i)));
    }
  }

  public List<ASN1IPAddressFamily> getBlocks() {
    return Collections.unmodifiableList(blocks);
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(blocks.toArray(new ASN1IPAddressFamily[0]));
  }

  public static IPAddrBlocks getInstance(Object obj) {
    if (obj instanceof IPAddrBlocks) {
      return (IPAddrBlocks) obj;
    } else if (obj instanceof ASN1Sequence) {
      return new IPAddrBlocks((ASN1Sequence) obj);
    } else if (obj != null) {
      return new IPAddrBlocks(ASN1Sequence.getInstance(obj));
    } else {
      throw new IllegalArgumentException("invalid obj: null");
    }
  }

}
