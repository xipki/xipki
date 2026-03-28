// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.misc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Asn1 Parser.
 *
 * <p>The parser builds a tree of {@link Asn1Object}. It supports short and long-form tag numbers,
 * definite length, and BER indefinite length for constructed objects.</p>
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1Parser {

  private Asn1Parser() {
  }

  /**
   * Tag Class enumeration.
   *
   * @author Lijun Liao (xipki)
   */
  public enum TagClass {
    UNIVERSAL, APPLICATION, CONTEXT_SPECIFIC, PRIVATE
  }

  /**
   * Asn1 Object.
   *
   * @author Lijun Liao (xipki)
   */
  public static class Asn1Object {

    private final TagClass tagClass;

    private final boolean constructed;

    private final int tagNumber;

    private final int headerLength;

    private final int valueLength;

    private final int startIndex;

    private final int endIndex;

    private final byte[] value;

    private final List<Asn1Object> children;

    private Asn1Object(TagClass tagClass, boolean constructed, int tagNumber, int headerLength,
                      int valueLength, int startIndex, int endIndex, byte[] value,
                      List<Asn1Object> children) {
      this.tagClass = tagClass;
      this.constructed = constructed;
      this.tagNumber = tagNumber;
      this.headerLength = headerLength;
      this.valueLength = valueLength;
      this.startIndex = startIndex;
      this.endIndex = endIndex;
      this.value = value;
      this.children = children;
    }

    public TagClass tagClass() {
      return tagClass;
    }

    public boolean constructed() {
      return constructed;
    }

    public int tagNumber() {
      return tagNumber;
    }

    public int headerLength() {
      return headerLength;
    }

    public int valueLength() {
      return valueLength;
    }

    public int startIndex() {
      return startIndex;
    }

    public int endIndex() {
      return endIndex;
    }

    public byte[] value() {
      return value.clone();
    }

    public List<Asn1Object> children() {
      return children;
    }
  }

  public static List<Asn1Object> parse(byte[] encoded) {
    if (encoded == null) {
      throw new IllegalArgumentException("encoded must not be null");
    }

    ParseResult result = parseAll(encoded, 0, encoded.length, false);
    return result.objects;
  }

  private static ParseResult parseAll(byte[] encoded, int offset, int endExclusive,
                                      boolean stopAtEoc) {
    List<Asn1Object> objects = new ArrayList<>();
    int cursor = offset;
    while (cursor < endExclusive) {
      if (stopAtEoc && isEoc(encoded, cursor, endExclusive)) {
        return new ParseResult(objects, cursor + 2);
      }

      ParseOneResult one = parseOne(encoded, cursor, endExclusive);
      objects.add(one.object);
      cursor = one.nextOffset;
    }

    if (stopAtEoc) {
      throw new IllegalArgumentException("missing end-of-content marker");
    }

    return new ParseResult(objects, cursor);
  }

  private static ParseOneResult parseOne(byte[] encoded, int offset, int endExclusive) {
    if (offset >= endExclusive) {
      throw new IllegalArgumentException("no ASN.1 object at offset " + offset);
    }

    int cursor = offset;
    int firstTagByte = unsigned(encoded[cursor++]);
    TagClass tagClass = decodeTagClass(firstTagByte);
    boolean constructed = (firstTagByte & 0x20) != 0;

    int tagNumber = firstTagByte & 0x1F;
    if (tagNumber == 0x1F) {
      tagNumber = 0;
      int guard = 0;
      while (true) {
        if (cursor >= endExclusive) {
          throw new IllegalArgumentException("truncated high-tag-number at offset " + offset);
        }
        int b = unsigned(encoded[cursor++]);
        guard++;
        if (guard > 6) {
          throw new IllegalArgumentException("high-tag-number too large at offset " + offset);
        }

        if ((tagNumber & 0xFE000000) != 0) {
          throw new IllegalArgumentException("high-tag-number overflow at offset " + offset);
        }
        tagNumber = (tagNumber << 7) | (b & 0x7F);

        if ((b & 0x80) == 0) {
          break;
        }
      }
    }

    if (cursor >= endExclusive) {
      throw new IllegalArgumentException("truncated length at offset " + offset);
    }

    int firstLenByte = unsigned(encoded[cursor++]);
    int valueStart = cursor;
    int valueLength;
    int nextOffset;
    List<Asn1Object> children;

    if (firstLenByte == 0x80) {
      if (!constructed) {
        throw new IllegalArgumentException(
            "indefinite length used for primitive at offset " + offset);
      }

      ParseResult childResult = parseAll(encoded, valueStart, endExclusive, true);
      children = Collections.unmodifiableList(childResult.objects);
      valueLength = childResult.nextOffset - valueStart - 2;
      nextOffset = childResult.nextOffset;
    } else if ((firstLenByte & 0x80) == 0) {
      valueLength = firstLenByte;
      nextOffset = valueStart + valueLength;
      if (nextOffset > endExclusive) {
        throw new IllegalArgumentException("value exceeds input at offset " + offset);
      }

      children = parseChildrenIfConstructed(encoded, constructed, valueStart, valueLength);
    } else {
      int lengthBytes = firstLenByte & 0x7F;
      if (lengthBytes == 0) {
        throw new IllegalArgumentException("invalid length form at offset " + offset);
      }
      if (lengthBytes > 4) {
        throw new IllegalArgumentException("length too large at offset " + offset);
      }
      if (cursor + lengthBytes > endExclusive) {
        throw new IllegalArgumentException("truncated long-form length at offset " + offset);
      }

      int len = 0;
      for (int i = 0; i < lengthBytes; i++) {
        len = (len << 8) | unsigned(encoded[cursor++]);
      }
      valueLength = len;
      valueStart = cursor;
      nextOffset = valueStart + valueLength;
      if (valueLength < 0 || nextOffset > endExclusive) {
        throw new IllegalArgumentException("value exceeds input at offset " + offset);
      }

      children = parseChildrenIfConstructed(encoded, constructed, valueStart, valueLength);
    }

    int headerLength = valueStart - offset;
    byte[] value = new byte[valueLength];
    System.arraycopy(encoded, valueStart, value, 0, valueLength);

    Asn1Object obj = new Asn1Object(tagClass, constructed, tagNumber, headerLength, valueLength,
        offset, nextOffset, value, children);
    return new ParseOneResult(obj, nextOffset);
  }

  private static List<Asn1Object> parseChildrenIfConstructed(
      byte[] encoded, boolean constructed, int valueStart, int valueLength) {
    if (!constructed) {
      return Collections.emptyList();
    }

    ParseResult childResult = parseAll(encoded, valueStart, valueStart + valueLength, false);
    return Collections.unmodifiableList(childResult.objects);
  }

  private static boolean isEoc(byte[] encoded, int offset, int endExclusive) {
    return offset + 1 < endExclusive && encoded[offset] == 0x00 && encoded[offset + 1] == 0x00;
  }

  private static TagClass decodeTagClass(int firstTagByte) {
    int code = (firstTagByte >>> 6) & 0x03;
    switch (code) {
      case 0:
        return TagClass.UNIVERSAL;
      case 1:
        return TagClass.APPLICATION;
      case 2:
        return TagClass.CONTEXT_SPECIFIC;
      case 3:
        return TagClass.PRIVATE;
      default:
        throw new IllegalStateException("should not happen");
    }
  }

  private static int unsigned(byte b) {
    return b & 0xFF;
  }

  private static class ParseResult {
    private final List<Asn1Object> objects;
    private final int nextOffset;

    private ParseResult(List<Asn1Object> objects, int nextOffset) {
      this.objects = objects;
      this.nextOffset = nextOffset;
    }
  }

  private static class ParseOneResult {
    private final Asn1Object object;
    private final int nextOffset;

    private ParseOneResult(Asn1Object object, int nextOffset) {
      this.object = object;
      this.nextOffset = nextOffset;
    }
  }

}
