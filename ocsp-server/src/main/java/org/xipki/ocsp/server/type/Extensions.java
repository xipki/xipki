// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type;

import java.util.List;

/**
 * ASN.1 Extensions.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class Extensions extends ASN1Type {

  private final List<Extension> extensions;

  private final int bodyLen;

  private final int encodedLen;

  public Extensions(List<Extension> extensions) {
    int len = 0;
    for (Extension m : extensions) {
      len += m.getEncodedLength();
    }

    this.bodyLen = len;
    this.encodedLen = getLen(bodyLen);
    this.extensions = extensions;
  }

  @Override
  public int getEncodedLength() {
    return encodedLen;
  }

  @Override
  public int write(byte[] out, int offset) {
    int idx = offset;
    idx += writeHeader((byte) 0x30, bodyLen, out, idx);
    for (Extension m : extensions) {
      idx += m.write(out, idx);
    }
    return idx - offset;
  }

}
