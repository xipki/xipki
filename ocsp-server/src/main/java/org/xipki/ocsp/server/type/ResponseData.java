// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type;

import java.time.Instant;
import java.util.List;

/**
 * ASN.1 ResponseData.
 *
 * @author Lijun Liao (xipki)
 */

public class ResponseData extends ASN1Type {

  private final int version;

  private final ResponderID responderId;

  private final Instant producedAt;

  private final List<SingleResponse> responses;

  private final Extensions extensions;

  private final int bodyLength;

  private final int encodedLength;

  public ResponseData(int version, ResponderID responderId, Instant producedAt,
                      List<SingleResponse> responses, Extensions extensions) {
    if (version < 0 || version > 127) {
      throw new IllegalArgumentException("invalid version: " + version);
    }
    this.version = version;
    this.responderId = responderId;
    this.producedAt = producedAt;
    this.responses = responses;
    this.extensions = extensions;

    int len = 0;
    if (version != 0) {
      len += 5;
    }
    len += responderId.encodedLength();

    // producedAt
    len += 17;

    // responses
    int responsesBodyLen = 0;
    for (SingleResponse sr : responses) {
      responsesBodyLen += sr.encodedLength();
    }
    len += getLen(responsesBodyLen);

    // extensions
    if (extensions != null) {
      len += getLen(extensions.encodedLength()); // explicit tag
    }

    this.bodyLength = len;
    this.encodedLength = getLen(bodyLength);
  } // constructor

  @Override
  public int encodedLength() {
    return encodedLength;
  }

  @Override
  public int write(byte[] out, int offset) {
    int idx = offset;
    idx += writeHeader((byte) 0x30, bodyLength, out, idx);

    // version
    if (version != 0) {
      idx += writeHeader((byte) 0xa0, 3, out, idx);
      idx += writeHeader((byte) 0x02, 1, out, idx);
      out[idx++] = (byte) version;
    }

    idx += responderId.write(out, idx);
    idx += writeGeneralizedTime(producedAt, out, idx);

    // responses
    int responsesBodyLen = 0;
    for (SingleResponse sr : responses) {
      responsesBodyLen += sr.encodedLength();
    }
    idx += writeHeader((byte) 0x30, responsesBodyLen, out, idx);
    for (SingleResponse sr : responses) {
      idx += sr.write(out, idx);
    }

    if (extensions != null) {
      idx += writeHeader((byte) 0xa1, extensions.encodedLength(), out, idx);
      idx += extensions.write(out, idx);
    }

    return idx - offset;
  } // method write

}
