// #THIRDPARTY
/*
 * JACOB - CBOR implementation in Java.
 *
 * (C) Copyright - 2013 - J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package org.xipki.util.cbor;

import org.xipki.util.Args;
import org.xipki.util.Hex;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import static org.xipki.util.cbor.CborConstants.*;

/**
 * Provides a CBOR parser.
 */
public class CborParse {

  private static final class IndentOutStream {
    private final byte[] prefix;
    private final OutputStream out;

    private boolean addPrefix = true;

    public IndentOutStream(OutputStream out, String prefix) {
      this.prefix = (prefix == null || prefix.isEmpty())
          ? null : prefix.getBytes(StandardCharsets.UTF_8);
      this.out = out;
    }

    private void writeText(String text) throws IOException {
      if (addPrefix) {
        if (prefix != null) {
          out.write(prefix);
        }
        addPrefix = false;
      }
      out.write(text.getBytes(StandardCharsets.UTF_8));
    }

    private void writeNewLine() throws IOException {
      out.write('\n');
      addPrefix = true;
    }

  }

  private static class MyBuffer {
    private byte[] buffer;

    private int count;

    private MyBuffer() {
      buffer = new byte[256];
    }

    private void ensureCap(int minCap) {
      int curCap = buffer.length;
      int minDiff = minCap - curCap;
      if (minDiff > 0) {
        buffer = Arrays.copyOf(buffer, curCap + Math.max(curCap, minDiff));
      }
    }

    private void write(int b) {
      ensureCap(count + 1);
      buffer[count++] = (byte) b;
    }

    private void write(byte[] buf, int off, int len) {
      ensureCap(count + len);
      System.arraycopy(buf, off, buffer, count, len);
      count += len;
    }

    private void reset() {
      count = 0;
    }

    private void unread() {
      if (count < 1) throw new IllegalStateException("could not unread");
      count--;
    }

    private byte[] toByteArray() {
      return Arrays.copyOf(buffer, count);
    }
  }

  private static class MyInputStream {
    private final PushbackInputStream is;
    private final MyBuffer buffer;
    private final AtomicInteger offset;

    private MyInputStream(PushbackInputStream is) {
      this.is = is;
      buffer = new MyBuffer();
      offset = new AtomicInteger();
    }

    private int read() throws IOException {
      int i = is.read();
      if (i != -1) {
        buffer.write(i);
        offset.getAndIncrement();
      }
      return i;
    }

    private int read(byte[] buf, int off, int len) throws IOException {
      int num = is.read(buf, off, len);
      if (num != -1) {
        buffer.write(buf, off, num);
        offset.getAndAdd(num);
      }
      return num;
    }

    private void unread(int val) throws IOException {
      is.unread(val);
      buffer.unread();
      offset.getAndDecrement();
    }

    private void resetBuffer() {
      buffer.reset();
    }

    private int getOffset() {
      return offset.get();
    }

    private byte[] getBufferedBytes() {
      return buffer.toByteArray();
    }

  }

  private static final BigInteger _2power64 = new BigInteger("10000000000000000", 16);

  private static final int numBytesPerLine = 24;

  private static final int numTextBytesPerLine = 16;

  private static final int numSpacesBeforeComment = 22;

  private final MyInputStream is;

  private IndentOutStream out;

  /**
   * Creates a new {@link CborParse} instance.
   *
   * @param encoded the CBOR-encoded data form.
   */
  public CborParse(byte[] encoded) {
    this(new ByteArrayInputStream(encoded));
  }

  /**
   * Creates a new {@link CborParse} instance.
   *
   * @param is the actual input stream to read the CBOR-encoded data from, cannot be <code>null</code>.
   */
  public CborParse(InputStream is) {
    Args.notNull(is, "is");
    if (is instanceof PushbackInputStream) {
      this.is = new MyInputStream((PushbackInputStream) is);
    } else {
      this.is = new MyInputStream(new PushbackInputStream(is));
    }
  }

  public void print() throws IOException, DecodeException {
    print(System.out, null);
  }

  public void print(int indentLevel) throws IOException, DecodeException {
    print(System.out, "  ".repeat(indentLevel));
  }

  public void print(String indentPrefix) throws IOException, DecodeException {
    print(System.out, indentPrefix);
  }

  public void print(OutputStream out) throws IOException, DecodeException {
    print(out, null);
  }

  public void print(OutputStream out, int indentLevel) throws IOException, DecodeException {
    print(out, "  ".repeat(indentLevel));
  }

  public void print(OutputStream out, String indentPrefix) throws IOException, DecodeException {
    this.out = new IndentOutStream(Args.notNull(out, "out"), indentPrefix);

    print0();

    ByteArrayOutputStream bout = new ByteArrayOutputStream(32);
    int read;
    byte[] buffer = new byte[2048];
    while ((read = is.read(buffer, 0, buffer.length)) != -1) {
      bout.write(buffer, 0, read);
    }

    int size = bout.size();
    if (size > 0) {
      writeLine("## " + size + " unused bytes:");
      byte[] remainingBytes = bout.toByteArray();
      writeBytesBlock(0, remainingBytes);
    }
  }

  private void print0() throws IOException, DecodeException {
    output(0, "");
    writeOffset(getOffset());
    writeNewLine();
  }

  private void output(int level, String prefix) throws IOException, DecodeException {
    CborType ctype = peekType();
    int addInfo = ctype.getAdditionalInfo();

    switch (ctype.getMajorType()) {
      case NULL:
        read1Byte();
        writeLine(level, readResetBuffer(), prefix + "<null>");
        break;
      case TYPE_NEGATIVE_INTEGER: {
        switch (addInfo) {
          case ONE_BYTE: {
            int v = readInt8();
            writeLine(level, readResetBuffer(), prefix + "nint8(" + v + ")");
            break;
          }
          case TWO_BYTES: {
            int v = readInt16();
            writeLine(level, readResetBuffer(), prefix + "nint16(" + v + ")");
            break;
          }
          case FOUR_BYTES: {
            long v = readInt32();
            writeLine(level, readResetBuffer(), prefix + "nint32(" + v + ")");
            break;
          }
          case EIGHT_BYTES: {
            long v = readInt64();
            String vText;
            if (v <= 0) {
              vText = Long.toString(v);
            } else {
              vText = BigInteger.valueOf(v).subtract(_2power64).toString();
            }

            writeLine(level, readResetBuffer(), prefix + "nint64(" + vText + ")");
            break;
          }
          default: {
            read1Byte();
            int v = -1 * (addInfo + 1);
            writeLine(level, readResetBuffer(), prefix + "simple(" + v + ")");
          }
        }
        break;
      }
      case TYPE_UNSIGNED_INTEGER: {
        switch (addInfo) {
          case ONE_BYTE: {
            read1Byte();
            int v = readUInt8();
            writeLine(level, readResetBuffer(), prefix + "uint8(" + v + ")");
            break;
          }
          case TWO_BYTES: {
            read1Byte();
            int v = readUInt16();
            writeLine(level, readResetBuffer(), prefix + "uint16(" + v + ")");
            break;
          }
          case FOUR_BYTES: {
            read1Byte();
            long v = readUInt32();
            writeLine(level, readResetBuffer(), prefix + "uint32(" + v + ")");
            break;
          }
          case EIGHT_BYTES: {
            read1Byte();
            long v = readUInt64();
            String vText;
            if (v > 0) {
              vText = Long.toString(v);
            } else {
              vText = _2power64.add(BigInteger.valueOf(v)).toString();
            }

            writeLine(level, readResetBuffer(), prefix + "uint64(" + vText + ")");
            break;
          }
          default: {
            if (addInfo >= 0 && addInfo <= 23) {
              read1Byte();
              writeLine(level, readResetBuffer(), prefix + "simple(" + addInfo + ")");
            }
          }
        }
        break;
      }
      case TYPE_TAG: {
        long t = readTag();
        writeLine(level, readResetBuffer(), prefix + "tag(" + t + ")");
        output(level + 1, "");
        break;
      }
      case TYPE_BYTE_STRING: {
        boolean isInfinite = addInfo == BREAK;
        if (isInfinite) {
          read1Byte();
          int blockIdx = 0;
          writeLine(level, readResetBuffer(), prefix + "bytes(*)");
          while (true) {
            if (skipBreak()) {
              writeLine(level + 1, readResetBuffer(), "<break>");
              break;
            }
            printByteString(level + 1, "[" + (blockIdx++) + "]: ");
          }
        } else {
          printByteString(level, prefix);
        }
        break;
      }
      case TYPE_TEXT_STRING: {
        boolean isInfinite = addInfo == BREAK;
        if (isInfinite) {
          read1Byte();
          int blockIdx = 0;
          writeLine(level, readResetBuffer(), prefix + "text(*)");
          while (true) {
            if (skipBreak()) {
              writeLine(level + 1, readResetBuffer(), "<break>");
              break;
            }
            printTextString(level + 1, "[" + (blockIdx++) + "]: ");
          }
        } else {
          printTextString(level, prefix);
        }
        break;
      }
      case TYPE_FLOAT_SIMPLE: {
        if (addInfo >=0 && addInfo <= 23) {
          read1Byte();
          switch (addInfo) {
            case NULL:
              writeLine(level, readResetBuffer(), prefix + "<null>");
              break;
            case FALSE:
              writeLine(level, readResetBuffer(), prefix + "false");
              break;
            case TRUE:
              writeLine(level, readResetBuffer(), prefix + "true");
              break;
            case UNDEFINED:
              writeLine(level, readResetBuffer(), prefix + "<undefined>");
              break;
            default:
              writeLine(level, readResetBuffer(), prefix + "float/simple(" + addInfo + ")");
          }
        } else if (addInfo == HALF_PRECISION_FLOAT) {
          double d = readHalfPrecisionFloat();
          writeLine(level, readResetBuffer(), prefix + "half precision float(" + d + ")");
        } else if (addInfo == SINGLE_PRECISION_FLOAT) {
          double d = readFloat();
          writeLine(level, readResetBuffer(), prefix + "float(" + d + ")");
        } else if (addInfo == DOUBLE_PRECISION_FLOAT) {
          double d = readDouble();
          writeLine(level, readResetBuffer(), prefix + "double(" + d + ")");
        } else if (addInfo == BREAK) {
          writeLine(level, readResetBuffer(), prefix + "<break>");
        } else {
          byte b = readSimpleValue();
          writeLine(level, readResetBuffer(), prefix + "float/simple(" + (b & 0xFF) + ")");
        }
        break;
      }
      case TYPE_ARRAY: {
        int len = readArrayLength();
        if (len == -1) {
          writeLine(level, readResetBuffer(), prefix + "array(*)");
          int idx = 0;
          while (true) {
            if (skipBreak()) {
              writeLine(level + 1, readResetBuffer(), "<break>");
              break;
            }

            output(level + 1, "[" + (idx++) + "]: ");
          }
        } else {
          writeLine(level, readResetBuffer(), prefix + "array(" + len + ")");
          for (int i = 0; i < len; i++) {
            output(level + 1, "[" + i + "]: ");
          }
        }
        break;
      }
      case TYPE_MAP: {
        int len = readMapLength();
        if (len == -1) {
          writeLine(level, readResetBuffer(), prefix + "map(*)");
          int idx = 0;
          while (true) {
            if (skipBreak()) {
              writeLine(level + 1, readResetBuffer(), "<break>");
              break;
            }

            output(level + 1, "[" + (idx) + "].key:   ");
            output(level + 1, "[" + (idx) + "].value: ");
            idx++;
          }
        } else {
          writeLine(level, readResetBuffer(), prefix + "map(" + len + ")");
          for (int i = 0; i < len; i++) {
            output(level + 1, "[" + i + "].key:   ");
            output(level + 1, "[" + i + "].value: ");
          }
        }
        break;
      }
      default:
        throw new DecodeException("unsupported cbor type " + ctype);
    }
  }

  private byte[] readResetBuffer() {
    byte[] bytes = is.getBufferedBytes();
    is.resetBuffer();
    return bytes;
  }

  private void writeLine(String text) throws IOException {
    writeText(text);
    writeNewLine();
  }

  private void printByteString(int level, String prefix) throws IOException, DecodeException {
    int len = (int) readByteStringLength();
    writeLine(level, readResetBuffer(), prefix + "bytes(" + len + ")");
    byte[] bytes = readExactBytes(len);
    if (bytes.length > 0) {
      writeBytesBlock(level + 1, bytes);
    }
  }

  private void printTextString(int level, String prefix)
      throws IOException, DecodeException {
    int len = (int) readTextStringLength();
    writeLine(level, readResetBuffer(), prefix + "text(" + len + ")");
    if (len == 0) {
      return;
    }

    byte[] bytes = readExactBytes(len);
    String text = new String(bytes, StandardCharsets.UTF_8);
    boolean sameLen = len == text.length();

    int offBase = getOffset() - bytes.length;
    is.resetBuffer();

    String ind = "  ".repeat(level + 1);

    int n = (len + numTextBytesPerLine - 1) / numTextBytesPerLine;

    int off = 0;
    for (int i = 0; i < n; i++, off += numTextBytesPerLine) {
      writeOffset(offBase + off);
      writeText(ind);

      int numBytesInLine = Math.min(numTextBytesPerLine, len - off);
      writeText(Hex.encodeUpper(bytes, off, numBytesInLine));

      if (sameLen) {
        String textPart = text.substring(off, off + numBytesInLine);
        int commentOff = Math.max(numSpacesBeforeComment, 2 * Math.min(numTextBytesPerLine, len) + 1);

        int numSpaces = commentOff - 2 * numBytesInLine;

        writeText(" ".repeat(numSpaces) + "# \"" + textPart + "\"");
      } else {
        // it is difficult to split the bytes, so we print
        // all text at the first line
        if (i == 0) {
          int numSpaces = Math.max(1, numSpacesBeforeComment - numBytesInLine * 2);
          writeText(" ".repeat(numSpaces) + "# \"" + text + "\"");
        }
      }

      writeNewLine();
    }
  }

  private byte[] readExactBytes(int len) throws IOException {
    byte[] out = new byte[len];
    int read;

    int off = 0;
    while (off < len && (read = is.read(out, off, len - off)) != -1) {
      off += read;
    }

    if (off < len) {
      throw new IOException(
          "in reaches end, but still expected " + (len - off) + " bytes");
    }
    return out;
  }

  private void writeBytesBlock(int level, byte[] data)
    throws IOException {
    int offBase = getOffset() - data.length;
    is.resetBuffer();

    int len = data.length;
    String ind = "  ".repeat(level);

    int n = (len + numBytesPerLine - 1) / numBytesPerLine;

    int off = 0;
    for (int i = 0; i < n; i++, off += numBytesPerLine) {
      writeOffset(offBase + off);
      writeText(ind);

      int numBytesInLine = Math.min(numBytesPerLine, len - off);
      writeText(Hex.encodeUpper(data, off, numBytesInLine));
      if (i != n - 1) {
        writeNewLine();
      }
    }

    writeNewLine();
  }

  private void writeLine(int level, byte[] data, String text)
    throws IOException {
    writeOffset(getOffset() - data.length);
    writeText("  ".repeat(level));

    int numSpaces = numSpacesBeforeComment;
    int len = data.length;
    if (len <= 1) {
      writeText(Hex.encodeUpper(data));
    } else {
      writeText(Hex.encodeUpper(data[0]));
      writeText(" ");
      writeText(Hex.encodeUpper(Arrays.copyOfRange(data, 1, len)));
      numSpaces--;
    }

    numSpaces = Math.max(1, numSpaces - 2 * data.length);

    writeText(" ".repeat(numSpaces));
    writeText("# " + text);
    writeNewLine();
  }

  private int getOffset() {
    return is.getOffset();
  }

  private void writeText(String text) throws IOException {
    out.writeText(text);
  }

  private void writeNewLine() throws IOException {
    out.writeNewLine();
  }

  private void writeOffset(int offset) throws IOException {
    String s = Integer.toString(offset);
    if (s.length() < 4) {
      s = " ".repeat(4 - s.length()) + s;
    }
    writeText(s + ": ");
  }

  private static void fail(String msg, Object... args) throws DecodeException {
    throw new DecodeException(String.format(msg, args));
  }

  /**
   * Peeks in the input stream for the upcoming type.
   *
   * @return the upcoming type in the stream, or <code>null</code> in case of an end-of-stream.
   * @throws IOException in case of I/O problems reading the CBOR-type from the underlying input stream.
   */
  private CborType peekType() throws IOException {
    int p = is.read();
    if (p < 0) {
      // EOF, nothing to peek at...
      throw new EOFException("reached stream end");
    }
    is.unread(p);
    return CborType.valueOf(p);
  }

  /**
   * read one bye
   * @return the read byte.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private int read1Byte() throws IOException {
    return is.read();
  }

  /**
   * Prolog to reading an array value in CBOR format.
   *
   * @return the number of elements in the array to read, or -1 in case of infinite-length arrays.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private int readArrayLength() throws IOException, DecodeException {
    long len = readMajorTypeWithSize(TYPE_ARRAY);
    if (len < -1 || len > Integer.MAX_VALUE) {
      // -1: break / infinite length
      throw new DecodeException("array length not in range [0, " + Integer.MAX_VALUE + "]");
    }
    return (int) len;
  }

  /**
   * Reads a "break"/stop value in CBOR format.
   *
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private void readBreak() throws IOException, DecodeException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, BREAK);
  }

  /**
   * Prolog to reading a byte string value in CBOR format.
   *
   * @return the number of bytes in the string to read, or -1 in case of infinite-length strings.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private long readByteStringLength() throws IOException, DecodeException {
    return readMajorTypeWithSize(TYPE_BYTE_STRING);
  }

  /**
   * Reads a double-precision float value in CBOR format.
   *
   * @return the read double value, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private double readDouble() throws IOException, DecodeException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, DOUBLE_PRECISION_FLOAT);

    return Double.longBitsToDouble(readUInt64());
  }

  /**
   * Reads a single-precision float value in CBOR format.
   *
   * @return the read float value, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private float readFloat() throws IOException, DecodeException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, SINGLE_PRECISION_FLOAT);

    return Float.intBitsToFloat((int) readUInt32());
  }

  /**
   * Reads a half-precision float value in CBOR format.
   *
   * @return the read half-precision float value, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE}
   *     are supported.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private double readHalfPrecisionFloat() throws IOException, DecodeException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, HALF_PRECISION_FLOAT);

    int half = readUInt16();
    int exp = (half >> 10) & 0x1f;
    int mant = half & 0x3ff;

    double val;
    if (exp == 0) {
      val = mant * Math.pow(2, -24);
    } else if (exp != 31) {
      val = (mant + 1024) * Math.pow(2, exp - 25);
    } else if (mant != 0) {
      val = Double.NaN;
    } else {
      val = Double.POSITIVE_INFINITY;
    }

    return ((half & 0x8000) == 0) ? val : -val;
  }

  /**
   * Prolog to reading a map of key-value pairs in CBOR format.
   *
   * @return the number of entries in the map, &gt;= 0.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private int readMapLength() throws IOException, DecodeException {
    long len = readMajorTypeWithSize(TYPE_MAP);
    if (len < -1 || len > Integer.MAX_VALUE) {
      // -1: break / infinite length
      throw new DecodeException("map length not in range [0, " + Integer.MAX_VALUE + "]");
    }
    return (int) len;

  }

  /**
   * Reads a single byte value in CBOR format.
   *
   * @return the read byte value.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private byte readSimpleValue() throws IOException, DecodeException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, ONE_BYTE);
    return (byte) readUInt8();
  }

  /**
   * Reads a semantic tag value in CBOR format.
   *
   * @return the read tag value.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private long readTag() throws IOException, DecodeException {
    return readUInt(readMajorType(TYPE_TAG), false /* breakAllowed */);
  }

  /**
   * Prolog to reading an UTF-8 encoded string value in CBOR format.
   *
   * @return the length of the string to read, or -1 in case of infinite-length strings.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private long readTextStringLength() throws IOException, DecodeException {
    return readMajorTypeWithSize(TYPE_TEXT_STRING);
  }

  /**
   * Reads the next major type from the underlying input stream, and verifies whether it matches the given expectation.
   *
   * @param majorType the expected major type, cannot be <code>null</code> (unchecked).
   * @return the read subtype, or payload, of the read major type.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private int readMajorType(int majorType) throws IOException, DecodeException {
    int ib = is.read();
    if (majorType != ((ib >>> 5) & 0x07)) {
      fail("Unexpected type: %s, expected: %s!", CborType.getName(ib), CborType.getName(majorType));
    }
    return ib & 0x1F;
  }

  /**
   * Reads the next major type from the underlying input stream, and verifies whether it matches the given
   * expectations.
   *
   * @param majorType the expected major type, cannot be <code>null</code> (unchecked);
   * @param subtype the expected subtype.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private void readMajorTypeExact(int majorType, int subtype) throws IOException, DecodeException {
    int st = readMajorType(majorType);
    if ((st ^ subtype) != 0) {
      fail("Unexpected subtype: %d, expected: %d!", st, subtype);
    }
  }

  /**
   * Reads the next major type from the underlying input stream, verifies whether it matches the given expectation,
   * and decodes the payload into a size.
   *
   * @param majorType the expected major type, cannot be <code>null</code> (unchecked).
   * @return the number of succeeding bytes, &gt;= 0, or -1 if an infinite-length type is read.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private long readMajorTypeWithSize(int majorType) throws IOException, DecodeException {
    return readUInt(readMajorType(majorType), true /* breakAllowed */);
  }

  /**
   * Reads an unsigned integer with a given length-indicator.
   *
   * @param length the length indicator to use;
   * @param breakAllowed whether break is allowed.
   * @return the read unsigned integer, as long value.
   * @throws IOException in case of I/O problems reading the unsigned integer from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private long readUInt(int length, boolean breakAllowed) throws IOException, DecodeException {
    return readUInt(length, breakAllowed, false);
  }

  private long readUInt(int length, boolean breakAllowed, boolean allow64Bit)
    throws IOException, DecodeException {
    long result = -1;
    if (length < ONE_BYTE) {
      result = length;
    } else if (length == ONE_BYTE) {
      result = readUInt8();
    } else if (length == TWO_BYTES) {
      result = readUInt16();
    } else if (length == FOUR_BYTES) {
      result = readUInt32();
    } else if (length == EIGHT_BYTES) {
      result = readUInt64();
      if (allow64Bit && result < 0) {
        return result;
      }
    } else if (breakAllowed && length == BREAK) {
      return -1;
    }

    if (result < 0) {
      fail("Not well-formed CBOR integer found, invalid length: %d!", result);
    }
    return result;
  }

  /**
   * Reads an unsigned 16-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  private int readUInt16() throws IOException {
    byte[] buf = readFully(new byte[2]);
    return (buf[0] & 0xFF) << 8 | (buf[1] & 0xFF);
  }

  /**
   * Reads an unsigned 32-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  private long readUInt32() throws IOException {
    byte[] buf = readFully(new byte[4]);
    return ((buf[0] & 0xFFL) << 24 | (buf[1] & 0xFF) << 16 | (buf[2] & 0xFF) << 8 | (buf[3] & 0xFF)) & 0xffffffffL;
  }

  /**
   * Reads an unsigned 64-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  private long readUInt64() throws IOException {
    byte[] buf = readFully(new byte[8]);
    return (buf[0] & 0xFFL) << 56 | (buf[1] & 0xFFL) << 48 | (buf[2] & 0xFFL) << 40 | (buf[3] & 0xFFL) << 32 |
      (buf[4] & 0xFFL) << 24 | (buf[5] & 0xFFL) << 16 | (buf[6] & 0xFFL) << 8 | (buf[7] & 0xFFL);
  }

  /**
   * Reads an unsigned 8-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  private int readUInt8() throws IOException {
    return is.read() & 0xff;
  }

  private int readInt8() throws IOException, DecodeException {
    int ib = is.read();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does an ones complement
    return (int) (ui ^ readUIntExact(ONE_BYTE, ib & 0x1f));
  }

  private int readInt16() throws IOException, DecodeException {
    int ib = is.read();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return (int) (ui ^ readUIntExact(TWO_BYTES, ib & 0x1f));
  }

  private long readInt32() throws IOException, DecodeException {
    int ib = is.read();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return ui ^ readUIntExact(FOUR_BYTES, ib & 0x1f);
  }

  private long readInt64() throws IOException, DecodeException {
    int ib = is.read();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return ui ^ readUIntExact(EIGHT_BYTES, ib & 0x1f);
  }

  private byte[] readFully(byte[] buf) throws IOException {
    int len = buf.length;
    int n = 0, off = 0;
    while (n < len) {
      int count = is.read(buf, off + n, len - n);
      if (count < 0) {
        throw new EOFException();
      }
      n += count;
    }
    return buf;
  }

  private boolean skipBreak() throws IOException, DecodeException {
    CborType type = peekType();
    if (type.getMajorType() == TYPE_FLOAT_SIMPLE
        && type.getAdditionalInfo() == BREAK) {
      readBreak();
      return true;
    } else {
      return false;
    }
  }

  private long expectIntegerType(int ib) throws DecodeException {
    int majorType = ((ib & 0xFF) >>> 5);
    if ((majorType != TYPE_UNSIGNED_INTEGER)
        && (majorType != TYPE_NEGATIVE_INTEGER)) {
      fail("Unexpected type: %s, expected type %s or %s!",
          CborType.getName(majorType),
          CborType.getName(TYPE_UNSIGNED_INTEGER),
          CborType.getName(TYPE_NEGATIVE_INTEGER));
    }

    return -majorType;
  }

  /**
   * Reads an unsigned integer with a given length-indicator.
   * @param expectedLength the expected length.
   * @param length the length indicator to use;
   * @return the read unsigned integer, as long value.
   * @throws IOException in case of I/O problems reading the unsigned integer
   *        from the underlying input stream.
   * @throws DecodeException in case of CBOR decoding problem.
   */
  private long readUIntExact(int expectedLength, int length)
      throws IOException, DecodeException {
    if ((expectedLength == -1 && length >= ONE_BYTE)
        || (expectedLength >= 0 && length != expectedLength)) {
      fail("Unexpected payload/length! Expected %s, but got %s.",
          CborDecoder.lengthToString(expectedLength),
          CborDecoder.lengthToString(length));
    }
    return readUInt(length, false /* breakAllowed */, true);
  }

}
