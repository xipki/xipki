// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Bounds-checked reader of DNS wire data. Every read beyond the end of the data
 * throws {@link DnsException}.
 *
 * @author Lijun Liao (xipki)
 */
public final class WireReader {

  private static final int MAX_POINTER_JUMPS = 16;

  private final byte[] data;

  private final int end;

  private int pos;

  public WireReader(byte[] data) {
    this(data, 0, data.length);
  }

  public WireReader(byte[] data, int offset, int len) {
    if (offset < 0 || len < 0 || offset + len > data.length) {
      throw new IllegalArgumentException("invalid offset or len");
    }
    this.data = data;
    this.pos = offset;
    this.end = offset + len;
  }

  public int position() {
    return pos;
  }

  public int remaining() {
    return end - pos;
  }

  private void need(int n) throws DnsException {
    if (n < 0 || end - pos < n) {
      throw new DnsException("truncated DNS data");
    }
  }

  public int u8() throws DnsException {
    need(1);
    return data[pos++] & 0xFF;
  }

  public int u16() throws DnsException {
    need(2);
    int v = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
    pos += 2;
    return v;
  }

  public long u32() throws DnsException {
    need(4);
    long v = ((long) (data[pos] & 0xFF) << 24) | ((data[pos + 1] & 0xFF) << 16)
        | ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF);
    pos += 4;
    return v;
  }

  public byte[] bytes(int n) throws DnsException {
    need(n);
    byte[] v = Arrays.copyOfRange(data, pos, pos + n);
    pos += n;
    return v;
  }

  public void skip(int n) throws DnsException {
    need(n);
    pos += n;
  }

  /**
   * Reads a name without compression, e.g. from canonical RDATA.
   */
  public DnsName name() throws DnsException {
    return name(null);
  }

  /**
   * Reads a name. If {@code message} is not {@code null}, compression pointers into it
   * are followed. A pointer must point backwards, and at most 16 pointers are followed.
   *
   * @param message the whole message, or {@code null} if compression is not allowed.
   * @return the name.
   * @throws DnsException if the name is invalid.
   */
  public DnsName name(byte[] message) throws DnsException {
    List<byte[]> labels = new ArrayList<>();
    int wireLen = 1;
    int jumps = 0;
    // position in the buffer being read: data (jumps == 0) or message
    byte[] buf = data;
    int p = pos;
    int bufEnd = end;

    while (true) {
      if (p >= bufEnd) {
        throw new DnsException("truncated DNS name");
      }

      int len = buf[p] & 0xFF;
      if (len == 0) {
        p++;
        break;
      }

      int kind = len & 0xC0;
      if (kind == 0xC0) {
        if (message == null) {
          throw new DnsException("compression pointer is not allowed here");
        }
        if (p + 1 >= bufEnd) {
          throw new DnsException("truncated compression pointer");
        }

        int target = ((len & 0x3F) << 8) | (buf[p + 1] & 0xFF);
        // In the message, the pointer must point before the pointer itself.
        int pointerPos = (jumps == 0) ? messageOffset(p, message) : p;
        if (target >= pointerPos) {
          throw new DnsException("compression pointer does not point backwards");
        }

        if (++jumps > MAX_POINTER_JUMPS) {
          throw new DnsException("too many compression pointers");
        }

        if (jumps == 1) {
          pos = p + 2;
        }
        buf = message;
        p = target;
        bufEnd = message.length;
        continue;
      } else if (kind != 0) {
        throw new DnsException("unsupported label type");
      }

      if (p + 1 + len > bufEnd) {
        throw new DnsException("truncated DNS label");
      }

      wireLen += 1 + len;
      if (wireLen > DnsName.MAX_WIRE_LENGTH) {
        throw new DnsException("DNS name too long");
      }

      byte[] label = new byte[len];
      for (int i = 0; i < len; i++) {
        label[i] = (byte) DnsName.lower(buf[p + 1 + i] & 0xFF);
      }
      labels.add(label);
      p += 1 + len;
    }

    if (jumps == 0) {
      pos = p;
    }
    return new DnsName(labels.toArray(new byte[0][]));
  }

  private int messageOffset(int p, byte[] message) throws DnsException {
    if (data != message) {
      // The reader works on a copy, e.g. RDATA: compression is not supported.
      throw new DnsException("compression pointer outside of message");
    }
    return p;
  }

}
