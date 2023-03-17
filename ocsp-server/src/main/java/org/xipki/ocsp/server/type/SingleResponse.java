// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type;

import java.util.Date;

/**
 * ASN.1 SingleResponse.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class SingleResponse extends ASN1Type {

  private final CertID certId;

  private final byte[] certStatus;

  private final Date thisUpdate;

  private final Date nextUpdate;

  private final Extensions extensions;

  private final int bodyLength;

  private final int encodedLength;

  public SingleResponse(CertID certId, byte[] certStatus, Date thisUpdate, Date nextUpdate, Extensions extensions) {
    this.certId = certId;
    this.certStatus = certStatus;
    this.thisUpdate = thisUpdate;
    this.nextUpdate = nextUpdate;
    this.extensions = extensions;

    int len = certId.getEncodedLength();
    len += certStatus.length;
    len += 17; // thisUpdate
    if (nextUpdate != null) {
      len += 2; // explicit tag
      len += 17;
    }

    if (extensions != null) {
      len += getLen(extensions.getEncodedLength()); // explicit tag
    }

    this.bodyLength = len;
    this.encodedLength = getLen(bodyLength);
  } // constructor

  @Override
  public int getEncodedLength() {
    return encodedLength;
  }

  @Override
  public int write(byte[] out, int offset) {
    int idx = offset;
    idx += writeHeader((byte) 0x30, bodyLength, out, idx);
    idx += certId.write(out, idx);
    idx += arraycopy(certStatus, out, idx);
    idx += writeGeneralizedTime(thisUpdate, out, idx);
    if (nextUpdate != null) {
      idx += writeHeader((byte) 0xa0, 17, out, idx);
      idx += writeGeneralizedTime(nextUpdate, out, idx);
    }

    if (extensions != null) {
      idx += writeHeader((byte) 0xa1, extensions.getEncodedLength(), out, idx);
      idx += extensions.write(out, idx);
    }
    return idx - offset;
  } // method write

}
