// License Apache License 2.0

package org.xipki.mgmt.web.ca;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.*;

/**
 * Definite-length DER only, bounded before allocation and without recursive ASN.1 decoding.
 *
 * @author palos
 */
public final class Der {
  public static final int LIMIT = 2 * 1024 * 1024;

  public record Value(int tag, byte[] content, byte[] encoded) {
    public Reader reader() {
      return new Reader(content);
    }

    public void require(int expected) {
      if (tag != expected) {
        throw invalid();
      }
    }
  }

  public static final class Reader {
    private final byte[] data;
    private int offset;

    public Reader(byte[] data) {
      if (data == null || data.length > LIMIT) {
        throw invalid();
      }
      this.data = data;
    }

    public boolean hasNext() {
      return offset < data.length;
    }

    public Value read() {
      int start = offset;
      if (data.length - offset < 2) {
        throw invalid();
      }
      int tag = data[offset++] & 255;
      if ((tag & 31) == 31) {
        throw invalid();
      }
      int len = data[offset++] & 255;
      if (len >= 128) {
        int count = len & 127;
        if (count == 0 || count > 3 || data.length - offset < count || data[offset] == 0) {
          throw invalid();
        }
        len = 0;
        for (int i = 0; i < count; i++) {
          len = (len << 8) | (data[offset++] & 255);
        }
        if (len < 128) {
          throw invalid();
        }
      }
      if (len > LIMIT || len > data.length - offset) {
        throw invalid();
      }
      byte[] content = Arrays.copyOfRange(data, offset, offset + len);
      offset += len;
      return new Value(tag, content, Arrays.copyOfRange(data, start, offset));
    }

    public Value read(int tag) {
      var value = read();
      value.require(tag);
      return value;
    }

    public void end() {
      if (hasNext()) {
        throw invalid();
      }
    }
  }

  public static Value single(byte[] data, int tag) {
    var r = new Reader(data);
    var v = r.read(tag);
    r.end();
    return v;
  }

  /**
   * Validate constructed containers iteratively so hostile nesting cannot consume the Java stack.
   */
  public static void validate(byte[] encoded) {
    record Frame(Reader reader, int depth) {}
    var stack = new ArrayDeque<Frame>();
    stack.push(new Frame(new Reader(encoded), 0));
    int count = 0;
    while (!stack.isEmpty()) {
      var frame = stack.peek();
      if (!frame.reader().hasNext()) {
        stack.pop();
        continue;
      }
      if (++count > 65536) {
        throw invalid();
      }
      var value = frame.reader().read();
      int tag = value.tag();
      byte[] c = value.content();
      if (tag == 0) {
        throw invalid();
      }
      if (tag == 1 && (c.length != 1 || (c[0] != 0 && c[0] != (byte) 255))) {
        throw invalid();
      }
      if ((tag == 2 || tag == 10)
          && (c.length == 0
              || (c.length > 1
                  && ((c[0] == 0 && (c[1] & 128) == 0)
                      || (c[0] == (byte) 255 && (c[1] & 128) != 0))))) {
        throw invalid();
      }
      if (tag == 3
          && (c.length == 0
              || c[0] < 0
              || c[0] > 7
              || (c.length == 1 && c[0] != 0)
              || (c.length > 1 && (c[c.length - 1] & ((1 << c[0]) - 1)) != 0))) {
        throw invalid();
      }
      if (tag == 5 && c.length != 0) {
        throw invalid();
      }
      if (tag == 6) {
        oid(value);
      }
      if ((tag & 32) != 0) {
        if (frame.depth() >= 32) {
          throw invalid();
        }
        stack.push(new Frame(value.reader(), frame.depth() + 1));
      }
    }
  }

  public static byte[] tagged(int tag, byte[] content) {
    if (content.length > LIMIT) {
      throw invalid();
    }
    var out = new ByteArrayOutputStream();
    out.write(tag);
    if (content.length < 128) {
      out.write(content.length);
    } else {
      int n = content.length > 65535 ? 3 : content.length > 255 ? 2 : 1;
      out.write(128 | n);
      for (int i = n - 1; i >= 0; i--) {
        out.write(content.length >>> (8 * i));
      }
    }
    out.writeBytes(content);
    return out.toByteArray();
  }

  public static byte[] sequence(byte[]... values) {
    return tagged(48, join(values));
  }

  public static byte[] join(byte[]... values) {
    var out = new ByteArrayOutputStream();
    for (byte[] v : values) {
      if (v.length > LIMIT - out.size()) {
        throw invalid();
      }
      out.writeBytes(v);
    }
    return out.toByteArray();
  }

  public static byte[] integer(BigInteger n) {
    return tagged(2, n.toByteArray());
  }

  public static byte[] bits(byte[] bytes) {
    return tagged(3, join(new byte[] {0}, bytes));
  }

  public static byte[] oid(String value) {
    var out = new ByteArrayOutputStream();
    String[] p = value.split("\\.");
    long first = Long.parseLong(p[0]), second = Long.parseLong(p[1]);
    if (first > 2 || first < 0 || second < 0 || (first < 2 && second > 39)) {
      throw invalid();
    }
    base128(out, 40 * first + second);
    for (int i = 2; i < p.length; i++) {
      base128(out, Long.parseLong(p[i]));
    }
    return tagged(6, out.toByteArray());
  }

  private static void base128(ByteArrayOutputStream out, long n) {
    if (n < 0) {
      throw invalid();
    }
    int size = 1;
    for (long v = n; v > 127; v >>>= 7) {
      size++;
    }
    for (int i = size - 1; i >= 0; i--) {
      out.write((int) ((n >>> (7 * i)) & 127) | (i == 0 ? 0 : 128));
    }
  }

  public static String oid(Value v) {
    v.require(6);
    if (v.content.length == 0) {
      throw invalid();
    }
    var parts = new ArrayList<Long>();
    long n = 0;
    boolean continued = false;
    for (byte b : v.content) {
      int x = b & 255;
      if (!continued && x == 128) {
        throw invalid();
      }
      if (n > (Long.MAX_VALUE >>> 7)) {
        throw invalid();
      }
      n = (n << 7) | (x & 127);
      continued = (x & 128) != 0;
      if (!continued) {
        parts.add(n);
        n = 0;
      }
    }
    if (continued) {
      throw invalid();
    }
    long f = parts.remove(0);
    var text =
        new StringBuilder()
            .append(f < 40 ? 0 : f < 80 ? 1 : 2)
            .append('.')
            .append(f < 80 ? f % 40 : f - 80);
    for (long p : parts) {
      text.append('.').append(p);
    }
    return text.toString();
  }

  private static IllegalArgumentException invalid() {
    return new IllegalArgumentException("Invalid or unsupported DER");
  }

  private Der() {}
}
