// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * Absolute DNS name. The labels are stored in canonical form (ASCII letters in
 * lower case, RFC 4034 section 6.1), so that two names are equal if and only if
 * they are equal in DNS.
 *
 * @author Lijun Liao (xipki)
 */
public final class DnsName {

  public static final DnsName ROOT = new DnsName(new byte[0][]);

  static final int MAX_WIRE_LENGTH = 255;

  static final int MAX_LABEL_LENGTH = 63;

  // labels[0] is the left-most label.
  private final byte[][] labels;

  private final int hashCode;

  DnsName(byte[][] labels) {
    this.labels = labels;
    this.hashCode = Arrays.deepHashCode(labels);
  }

  /**
   * Parses a host name in presentation format, e.g. {@code _acme-challenge.example.org}.
   * A trailing dot is optional. Only the letters, digits, '-' and '_' are allowed.
   *
   * @param name the name.
   * @return the absolute name.
   * @throws IllegalArgumentException if the name is invalid.
   */
  public static DnsName of(String name) {
    if (name.equals(".")) {
      return ROOT;
    }

    String str = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
    String[] tokens = str.split("\\.", -1);
    byte[][] labels = new byte[tokens.length][];
    int wireLen = 1;
    for (int i = 0; i < tokens.length; i++) {
      String token = tokens[i];
      int len = token.length();
      if (len == 0 || len > MAX_LABEL_LENGTH) {
        throw new IllegalArgumentException("invalid label length in DNS name '" + name + "'");
      }

      byte[] label = new byte[len];
      for (int j = 0; j < len; j++) {
        char c = token.charAt(j);
        boolean valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!valid) {
          throw new IllegalArgumentException("invalid character in DNS name '" + name + "'");
        }
        label[j] = (byte) lower(c);
      }
      labels[i] = label;
      wireLen += 1 + len;
    }

    if (wireLen > MAX_WIRE_LENGTH) {
      throw new IllegalArgumentException("DNS name too long '" + name + "'");
    }
    return new DnsName(labels);
  }

  static int lower(int c) {
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
  }

  public int labelCount() {
    return labels.length;
  }

  public boolean isRoot() {
    return labels.length == 0;
  }

  /**
   * Returns the name without the left-most label.
   */
  public DnsName parent() {
    if (labels.length == 0) {
      throw new IllegalStateException("root has no parent");
    }
    return new DnsName(Arrays.copyOfRange(labels, 1, labels.length));
  }

  /**
   * Returns whether this name equals {@code other} or is below it.
   */
  public boolean isSubdomainOf(DnsName other) {
    int offset = labels.length - other.labels.length;
    if (offset < 0) {
      return false;
    }

    for (int i = 0; i < other.labels.length; i++) {
      if (!Arrays.equals(labels[offset + i], other.labels[i])) {
        return false;
      }
    }
    return true;
  }

  /**
   * Returns whether this name is strictly below {@code other}.
   */
  public boolean isProperSubdomainOf(DnsName other) {
    return labels.length > other.labels.length && isSubdomainOf(other);
  }

  /**
   * Returns the uncompressed wire format, which is also the canonical form.
   */
  public byte[] toWire() {
    ByteArrayOutputStream out = new ByteArrayOutputStream(MAX_WIRE_LENGTH);
    writeTo(out);
    return out.toByteArray();
  }

  void writeTo(ByteArrayOutputStream out) {
    for (byte[] label : labels) {
      out.write(label.length);
      out.write(label, 0, label.length);
    }
    out.write(0);
  }

  @Override
  public boolean equals(Object obj) {
    return obj == this
        || (obj instanceof DnsName && Arrays.deepEquals(labels, ((DnsName) obj).labels));
  }

  @Override
  public int hashCode() {
    return hashCode;
  }

  @Override
  public String toString() {
    if (labels.length == 0) {
      return ".";
    }

    StringBuilder sb = new StringBuilder();
    for (byte[] label : labels) {
      for (byte b : label) {
        int c = b & 0xFF;
        boolean plain = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c == '-' || c == '_' || c == '*';
        if (plain) {
          sb.append((char) c);
        } else {
          sb.append('\\').append(c / 100).append(c / 10 % 10).append(c % 10);
        }
      }
      sb.append('.');
    }
    return sb.toString();
  }

}
