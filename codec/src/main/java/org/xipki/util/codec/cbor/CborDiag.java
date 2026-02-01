// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.codec.cbor;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicInteger;

import static org.xipki.util.codec.cbor.CborConstants.*;

/**
 * Provides a CBOR parser.
 * @author Lijun Liao (xipki)
 */
public class CborDiag {

  protected static final class LongWithType {

    private final CborType type;

    private final long value;

    public LongWithType(CborType type, long value) {
      this.type = type;
      this.value = value;
    }

    @Override
    public String toString() {
      return getIntegerTypeDesc(type) + "(" + value + ")";
    }

    public CborType type() {
      return type;
    }

    public long value() {
      return value;
    }

  }

  protected static final class IntWithType {

    private final CborType type;

    private final int value;

    public IntWithType(CborType type, int value) {
      this.type = type;
      this.value = value;
    }

    @Override
    public String toString() {
      return getIntegerTypeDesc(type) + "(" + value + ")";
    }

    public CborType type() {
      return type;
    }

    public int value() {
      return value;
    }

  }

  protected static final class IndentOutStream {

    private final byte[] prefix;
    private final OutputStream out;

    private boolean addPrefix = true;

    private int lineOffset = 0;

    public IndentOutStream(OutputStream out, String prefix) {
      this.prefix = (prefix == null || prefix.isEmpty())
          ? null : prefix.getBytes(StandardCharsets.UTF_8);
      this.out = out;
    }

    protected void writeText(String text) throws CodecException {
      try {
        if (addPrefix) {
          if (prefix != null) {
            out.write(prefix);
            lineOffset += prefix.length;
          }
          addPrefix = false;
        }

        out.write(text.getBytes(StandardCharsets.UTF_8));
        lineOffset += text.length();
      } catch (IOException e) {
        throw new CodecException(e);
      }
    }

    protected void writeNewLine() throws CodecException {
      try {
        out.write('\n');
        lineOffset = 0;
        addPrefix = true;
      } catch (IOException e) {
        throw new CodecException(e);
      }
    }

    public int lineOffset() {
      return lineOffset;
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
    private final int totalSize;

    private MyInputStream(PushbackInputStream is) {
      this.is = is;
      int available;
      try {
        available = is.available();
      } catch (IOException e) {
        available = 9999;
      }
      totalSize = available;
      buffer = new MyBuffer();
      offset = new AtomicInteger();
    }

    private int read() throws CodecException {
      try {
        int i = is.read();
        if (i != -1) {
          buffer.write(i);
          offset.getAndIncrement();
        }
        return i;
      } catch (IOException e) {
        throw new CodecException(e);
      }
    }

    private int read(byte[] buf, int off, int len) throws CodecException {
      try {
        int num = is.read(buf, off, len);
        if (num != -1) {
          buffer.write(buf, off, num);
          offset.getAndAdd(num);
        }
        return num;
      } catch (IOException e) {
        throw new CodecException(e);
      }
    }

    private void unread(int val) throws CodecException {
      try {
        is.unread(val);
        buffer.unread();
        offset.getAndDecrement();
      } catch (IOException e) {
        throw new CodecException(e);
      }
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

  private static final BigInteger _2power64 =
      new BigInteger("10000000000000000", 16);

  private int numBytesPerLine = 32;

  private int numTextBytesPerLine = 18;

  private int numSpacesBeforeComment = 22;

  private int maxCharsPerLine = 80;

  private final MyInputStream is;

  private final boolean printEofOffset;

  protected final int offsetLen;

  private IndentOutStream out;

  /**
   * Creates a new {@link CborDiag} instance.
   *
   * @param encoded the CBOR-encoded data form.
   */
  public CborDiag(byte[] encoded) {
    this(encoded, true);
  }

  public CborDiag(byte[] encoded, boolean printEofOffset) {
    this(new ByteArrayInputStream(encoded), printEofOffset);
  }

  /**
   * Creates a new {@link CborDiag} instance.
   *
   * @param is the actual input stream to read the CBOR-encoded data from,
   *          cannot be <code>null</code>.
   */
  public CborDiag(InputStream is) {
    this(is, true);
  }

  public CborDiag(InputStream is, boolean printEofOffset) {
    Args.notNull(is, "is");
    if (is instanceof PushbackInputStream) {
      this.is = new MyInputStream((PushbackInputStream) is);
    } else {
      this.is = new MyInputStream(new PushbackInputStream(is));
    }
    this.printEofOffset = printEofOffset;
    int size = this.is.totalSize;
    this.offsetLen = size < 10 ? 1
        : size < 100 ? 2
        : size < 1000 ? 3
        : size < 10000 ? 4
        : size < 100000 ? 5
        : 6;
  }

  public int numSpacesBeforeComment() {
    return numSpacesBeforeComment;
  }

  public void setNumSpacesBeforeComment(int numSpacesBeforeComment) {
    this.numSpacesBeforeComment = numSpacesBeforeComment;
  }

  public void setMaxCharsPerLine(int maxCharsPerLine) {
    this.maxCharsPerLine = maxCharsPerLine;
  }

  public void setNumTextBytesPerLine(int numTextBytesPerLine) {
    this.numTextBytesPerLine = numTextBytesPerLine;
  }

  public void setNumBytesPerLine(int numBytesPerLine) {
    this.numBytesPerLine = numBytesPerLine;
  }

  public void print() throws CodecException {
    print(System.out, null);
  }

  public void print(int indentLevel) throws CodecException {
    print(System.out, "  ".repeat(indentLevel));
  }

  public void print(String indentPrefix) throws CodecException {
    print(System.out, indentPrefix);
  }

  public void print(OutputStream out) throws CodecException {
    print(out, null);
  }

  public void print(OutputStream out, int indentLevel)
      throws CodecException {
    print(out, "  ".repeat(indentLevel));
  }

  public void print(OutputStream out, String indentPrefix)
      throws CodecException {
    this.out = new IndentOutStream(Args.notNull(out, "out"), indentPrefix);

    print0();

    ByteArrayOutputStream bout = new ByteArrayOutputStream(32);
    int read;
    byte[] buffer = new byte[2048];
    while ((read = is.read(buffer, 0, buffer.length)) != -1) {
      bout.write(buffer, 0, read);
    }

    int size = bout.size();
    if (printEofOffset || size > 0) {
      writeOffset(getOffset());
      writeNewLine();
    }

    if (size > 0) {
      writeLine("## " + size + " unused bytes:");
      byte[] remainingBytes = bout.toByteArray();
      writeBytesBlock(0, remainingBytes);
    }
  }

  protected void print0() throws CodecException {
    output(0, "");
  }

  protected void output(int level, String prefix)
      throws CodecException {
    CborType ctype = peekType();
    int addInfo = ctype.additionalInfo();

    switch (ctype.majorType()) {
      case NULL:
        read1Byte();
        writeLine(level, readResetBuffer(), concat(prefix, "<null>"));
        break;
      case TYPE_NEGATIVE_INTEGER: {
        switch (addInfo) {
          case ONE_BYTE: {
            int v = readInt8();
            writeLine(level, readResetBuffer(),
                concat(prefix, "nint8(" + v + ")"));
            break;
          }
          case TWO_BYTES: {
            int v = readInt16();
            writeLine(level, readResetBuffer(),
                concat(prefix, "nint16(" + v + ")"));
            break;
          }
          case FOUR_BYTES: {
            long v = readInt32();
            writeLine(level, readResetBuffer(),
                concat(prefix, "=nint32(" + v + ")"));
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

            writeLine(level, readResetBuffer(),
                concat(prefix, "nint64(" + vText + ")"));
            break;
          }
          default: {
            read1Byte();
            int v = -1 * (addInfo + 1);
            writeLine(level, readResetBuffer(),
                concat(prefix, "simple-nint(" + v + ")"));
          }
        }
        break;
      }
      case TYPE_UNSIGNED_INTEGER: {
        switch (addInfo) {
          case ONE_BYTE: {
            read1Byte();
            int v = readUInt8();
            writeLine(level, readResetBuffer(),
                concat(prefix, "uint8(" + v + ")"));
            break;
          }
          case TWO_BYTES: {
            read1Byte();
            int v = readUInt16();
            writeLine(level, readResetBuffer(),
                concat(prefix, "uint16(" + v + ")"));
            break;
          }
          case FOUR_BYTES: {
            read1Byte();
            long v = readUInt32();
            writeLine(level, readResetBuffer(),
                concat(prefix, "uint32(" + v + ")"));
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

            writeLine(level, readResetBuffer(),
                concat(prefix, "uint64(" + vText + ")"));
            break;
          }
          default: {
            if (addInfo >= 0 && addInfo <= 23) {
              read1Byte();
              writeLine(level, readResetBuffer(),
                  concat(prefix, "simple-uint(" + addInfo + ")"));
            }
          }
        }
        break;
      }
      case TYPE_TAG: {
        long t = readTag();
        writeLine(level, readResetBuffer(), concat(prefix, "tag(" + t + ")"));
        output(level + 1, "");
        break;
      }
      case TYPE_BYTE_STRING: {
        boolean isInfinite = addInfo == BREAK;
        if (isInfinite) {
          read1Byte();
          int blockIdx = 0;
          writeLine(level, readResetBuffer(), concat(prefix, "byte[*]"));
          while (true) {
            if (skipBreak()) {
              writeLine(level + 1, readResetBuffer(), "<break>");
              break;
            }
            printByteString(level + 1, "[" + (blockIdx++) + "]");
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
          writeLine(level, readResetBuffer(), concat(prefix, "char[*]"));
          while (true) {
            if (skipBreak()) {
              writeLine(level + 1, readResetBuffer(), "<break>");
              break;
            }
            printTextString(level + 1, "[" + (blockIdx++) + "]");
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
              writeLine(level, readResetBuffer(), concat(prefix, "<null>"));
              break;
            case FALSE:
              writeLine(level, readResetBuffer(), concat(prefix, "false"));
              break;
            case TRUE:
              writeLine(level, readResetBuffer(), concat(prefix, "true"));
              break;
            case UNDEFINED:
              writeLine(level, readResetBuffer(),
                  concat(prefix, "<undefined>"));
              break;
            default:
              writeLine(level, readResetBuffer(),
                  concat(prefix, "float/simple(" + addInfo + ")"));
          }
        } else if (addInfo == HALF_PRECISION_FLOAT) {
          double d = readHalfPrecisionFloat();
          writeLine(level, readResetBuffer(),
              concat(prefix, "half precision float(" + d + ")"));
        } else if (addInfo == SINGLE_PRECISION_FLOAT) {
          double d = readFloat();
          writeLine(level, readResetBuffer(),
              concat(prefix, "float(" + d + ")"));
        } else if (addInfo == DOUBLE_PRECISION_FLOAT) {
          double d = readDouble();
          writeLine(level, readResetBuffer(),
              concat(prefix, "double(" + d + ")"));
        } else if (addInfo == BREAK) {
          writeLine(level, readResetBuffer(), concat(prefix, "<break>"));
        } else {
          byte b = readSimpleValue();
          writeLine(level, readResetBuffer(),
              concat(prefix, "float/simple(" + (b & 0xFF) + ")"));
        }
        break;
      }
      case TYPE_ARRAY: {
        int len = readArrayLength();
        if (len == -1) {
          writeLine(level, readResetBuffer(), concat(prefix, "array[*]"));
          int idx = 0;
          while (true) {
            if (skipBreak()) {
              writeLine(level + 1, readResetBuffer(), "<break>");
              break;
            }

            output(level + 1, "[" + (idx++) + "]");
          }
        } else {
          writeLine(level, readResetBuffer(),
              concat(prefix, "array[" + len + "]"));
          for (int i = 0; i < len; i++) {
            output(level + 1, "[" + i + "]");
          }
        }
        break;
      }
      case TYPE_MAP: {
        int len = readMapLength();
        if (len == -1) {
          writeLine(level, readResetBuffer(), concat(prefix, "map{*}"));
          int idx = 0;
          while (true) {
            if (skipBreak()) {
              writeLine(level + 1, readResetBuffer(), "<break>");
              break;
            }

            output(level + 1, "[" + (idx) + "].key  ");
            output(level + 1, "[" + (idx) + "].value");
            idx++;
          }
        } else {
          writeLine(level, readResetBuffer(),
              concat(prefix, "map(" + len + ")"));
          for (int i = 0; i < len; i++) {
            output(level + 1, "[" + i + "].key  ");
            output(level + 1, "[" + i + "].value");
          }
        }
        break;
      }
      default:
        throw new CodecException("unsupported cbor type " + ctype);
    }
  }

  protected LongWithType readLongWithType() throws CodecException {
    CborType type = peekType();
    long value = readLong();
    return new LongWithType(type, value);
  }

  protected IntWithType readIntWithType() throws CodecException {
    CborType type = peekType();
    int value = readInt();
    return new IntWithType(type, value);
  }

  protected static String getIntegerTypeDesc(CborType ctype) {
    int addInfo = ctype.additionalInfo();
    int majorType = ctype.majorType();
    if (majorType == TYPE_NEGATIVE_INTEGER) {
      switch (addInfo) {
        case ONE_BYTE:
          return "nint8";
        case TWO_BYTES:
          return "nint16";
        case FOUR_BYTES:
          return "nint32";
        case EIGHT_BYTES:
          return "nint64";
        default:
          return "simple-nint";
      }
    } else if (majorType ==TYPE_UNSIGNED_INTEGER) {
      switch (addInfo) {
        case ONE_BYTE:
          return "uint8";
        case TWO_BYTES:
          return "uint16";
        case FOUR_BYTES:
          return "uint32";
        case EIGHT_BYTES:
          return "uint64";
        default:
          return "simple-uint";
      }
    } else {
      throw new IllegalArgumentException(ctype + " is not expected type");
    }
  }

  protected byte[] readResetBuffer() {
    byte[] bytes = is.getBufferedBytes();
    is.resetBuffer();
    return bytes;
  }

  protected void writeLine(String text) throws CodecException {
    writeText(text);
    writeNewLine();
  }

  protected byte[] printByteString(int level, String prefix)
      throws CodecException {
    int len = readByteStringLength();
    writeLine(level, readResetBuffer(), concat(prefix, "byte[" + len + "]"));
    byte[] bytes = readExactBytes(len);
    if (bytes.length > 0) {
      writeBytesBlock(level + 1, bytes);
    }
    return bytes;
  }

  protected void printTextString(int level, String prefix)
      throws CodecException {
    int len = (int) readTextStringLength();
    writeLine(level, readResetBuffer(), concat(prefix, "char[" + len + "]"));
    if (len == 0) {
      return;
    }

    byte[] bytes = readExactBytes(len);
    String text = new String(bytes, StandardCharsets.UTF_8);
    boolean sameLen = (len == text.length());

    int offBase = getOffset() - bytes.length;
    is.resetBuffer();

    String ind = "  ".repeat(level + 1);

    int x = maxCharsPerLine - 4 // offset with 4 chars
        - 2 // ": "
        - ind.length() - 5;
    int numPerLine = Math.min(x, numTextBytesPerLine * 3) / 3;

    int n = (len + numPerLine - 1) / numPerLine;

    int off = 0;
    for (int i = 0; i < n; i++, off += numPerLine) {
      writeOffset(offBase + off);
      writeText(ind);

      int numBytesInLine = Math.min(numPerLine, len - off);
      writeText(Hex.encodeUpper(bytes, off, numBytesInLine));

      if (sameLen) {
        String textPart = text.substring(off, off + numBytesInLine);
        int commentOff =
            Math.max(numPerLine, 2 * Math.min(numPerLine, len) + 1);

        int numSpaces = commentOff - 2 * numBytesInLine;
        writeText(" ".repeat(numSpaces) + "# \"" + textPart + "\"");
      } else {
        // it is difficult to split the bytes, so we print
        // all text at the first line
        if (i == 0) {
          int numSpaces =
              Math.max(1, numSpacesBeforeComment - numBytesInLine * 2);
          writeText(" ".repeat(numSpaces) + "# \"" + text + "\"");
        }
      }

      writeNewLine();
    }
  }

  protected byte[] readExactBytes(int len) throws CodecException {
    byte[] out = new byte[len];
    int read;

    int off = 0;
    while (off < len && (read = is.read(out, off, len - off)) != -1) {
      off += read;
    }

    if (off < len) {
      throw new CodecException(
          "in reaches end, but still expected " + (len - off) + " bytes");
    }
    return out;
  }

  protected void writeBytesBlock(int level, byte[] data)
    throws CodecException {
    int offBase = getOffset() - data.length;
    is.resetBuffer();

    int len = data.length;
    String ind = "  ".repeat(level);

    int numPerLine = Math.min(numBytesPerLine,
        (maxCharsPerLine - 6 - ind.length()) / 2);

    int n = (len + numPerLine - 1) / numPerLine;

    int off = 0;
    for (int i = 0; i < n; i++, off += numPerLine) {
      writeOffset(offBase + off);
      writeText(ind);

      int numBytesInLine = Math.min(numPerLine, len - off);
      writeText(Hex.encodeUpper(data, off, numBytesInLine));
      if (i != n - 1) {
        writeNewLine();
      }
    }

    writeNewLine();
  }

  protected void writeLine(int level, byte[] data, String text)
    throws CodecException {
    writeLine(level, data, true, text);
  }

  protected void writeLine(int level, byte[] data, boolean firstByteIsTag,
                           String text)
    throws CodecException {
    writeOffset(getOffset() - data.length);
    writeText("  ".repeat(level));

    int numSpaces = numSpacesBeforeComment;
    int len = data.length;
    if (len <= 1) {
      writeText(Hex.encodeUpper(data));
    } else {
      if (firstByteIsTag) {
        writeText(Hex.encodeUpper(data[0]));
        writeText(" ");
        writeText(Hex.encodeUpper(Arrays.copyOfRange(data, 1, len)));
      } else {
        writeText(" ");
        writeText(Hex.encodeUpper(data));
      }
      numSpaces--;
    }

    numSpaces = Math.max(1, numSpaces - 2 * data.length);

    writeText(" ".repeat(numSpaces));
    int textLen = text.length();
    int lineOffset = out.lineOffset;;

    if (lineOffset + 2 + textLen < maxCharsPerLine) {
      writeText("# " + text);
    } else {
      // split the comment to multiple lines
      String leading = "";
      if (text.startsWith("[")) {
        int idx = text.indexOf("]: ", 1);
        if (idx == -1) {
          idx = text.indexOf("]. ", 1);
        }

        if (idx != -1) {
          leading = text.substring(0, idx + 3);
          text = text.substring(idx + 3);
        }
      }

      int numPerLine = maxCharsPerLine - lineOffset - 2 - leading.length();
      List<String> splitTexts = splitText(text, numPerLine);
      boolean firstLine = true;
      for (String line0 : splitTexts) {
        if (firstLine) {
          firstLine = false;
          writeText("# " + leading + line0);
        } else {
          writeNewLine();
          writeText(" ".repeat(lineOffset) + "# " +
              " ".repeat(leading.length()) + line0);
        }
      }
    }

    writeNewLine();
  }

  private static List<String> splitText(String text, int numPerLine) {
    StringTokenizer tokenizer = new StringTokenizer(text, " ");
    List<String> tokens = new LinkedList<>();
    while (tokenizer.hasMoreTokens()) {
      tokens.add(tokenizer.nextToken());
    }

    List<String> lines = new ArrayList<>();

    String line = "";
    for (String token : tokens) {
      if (line.isEmpty()) {
        line += token;
      } else if (line.length() + 1 + token.length() <= numPerLine) {
        line += " " + token;
      } else {
        lines.add(line);
        line = token;
      }

      if (line.length() >= numPerLine) {
        lines.add(line);
        line = "";
      }
    }

    if (!line.isEmpty()) {
      lines.add(line);
    }

    return lines;
  }

  protected int getOffset() {
    return is.getOffset();
  }

  protected void writeText(String text) throws CodecException {
    out.writeText(text);
  }

  protected void writeNewLine() throws CodecException {
    out.writeNewLine();
  }

  protected void writeOffset(int offset) throws CodecException {
    String s = Integer.toString(offset);
    if (s.length() < offsetLen) {
      s = " ".repeat(offsetLen - s.length()) + s;
    }
    writeText(s + ": ");
  }

  protected static void fail(String msg, Object... args) throws CodecException {
    throw new CodecException(String.format(msg, args));
  }

  /**
   * Peeks in the input stream for the upcoming type.
   *
   * @return the upcoming type in the stream, or <code>null</code> in case of
   *         an end-of-stream.
   * @throws CodecException in case of I/O problems reading the CBOR-type from
   *         the underlying input stream.
   */
  protected CborType peekType() throws CodecException {
    int p = is.read();
    if (p < 0) {
      // EOF, nothing to peek at...
      throw new CodecException("reached stream end");
    }
    is.unread(p);
    return CborType.valueOf(p);
  }

  /**
   * read one bye
   * @return the read byte.
   * @throws CodecException in case of I/O problems reading the CBOR-encoded
   *         value from the underlying input stream.
   */
  protected int read1Byte() throws CodecException {
    return is.read();
  }

  /**
   * Prolog to reading an array value in CBOR format.
   *
   * @return the number of elements in the array to read, or -1 in case of
   *         infinite-length arrays.
   * @throws CodecException in case of I/O problems reading the CBOR-encoded
   *         value from the underlying input stream.
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected int readArrayLength() throws CodecException {
    long len = readMajorTypeWithSize(TYPE_ARRAY);
    if (len < -1 || len > Integer.MAX_VALUE) {
      // -1: break / infinite length
      throw new CodecException(
          "array length not in range [0, " + Integer.MAX_VALUE + "]");
    }
    return (int) len;
  }

  /**
   * Reads a "break"/stop value in CBOR format.
   *
   * @throws CodecException in case of I/O problems reading the CBOR-encoded
   *         value from the underlying input stream.
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected void readBreak() throws CodecException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, BREAK);
  }

  /**
   * Prolog to reading a byte string value in CBOR format.
   *
   * @return the number of bytes in the string to read, or -1 in case of
   *         infinite-length strings.
   * @throws CodecException in case of I/O problems reading the CBOR-encoded
   *         value from the underlying input stream.
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected int readByteStringLength() throws CodecException {
    long v = readMajorTypeWithSize(TYPE_BYTE_STRING);
    if (v < Integer.MIN_VALUE || v > Integer.MAX_VALUE) {
      throw new CodecException("value is out of range of int32");
    }
    return (int) v;
  }

  /**
   * Reads a double-precision float value in CBOR format.
   *
   * @return the read double value, values from {@link Float#MIN_VALUE} to
   *         {@link Float#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems reading the CBOR-encoded
   *         value from the underlying input stream.
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected double readDouble() throws CodecException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, DOUBLE_PRECISION_FLOAT);

    return Double.longBitsToDouble(readUInt64());
  }

  /**
   * Reads a single-precision float value in CBOR format.
   *
   * @return the read float value, values from {@link Float#MIN_VALUE} to
   *         {@link Float#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems reading the CBOR-encoded
   *          value from the underlying input stream.
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected float readFloat() throws CodecException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, SINGLE_PRECISION_FLOAT);

    return Float.intBitsToFloat((int) readUInt32());
  }

  /**
   * Reads a half-precision float value in CBOR format.
   *
   * @return the read half-precision float value, values from
   *         {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected double readHalfPrecisionFloat() throws CodecException {
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
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected int readMapLength() throws CodecException {
    long len = readMajorTypeWithSize(TYPE_MAP);
    if (len < -1 || len > Integer.MAX_VALUE) {
      // -1: break / infinite length
      throw new CodecException(
          "map length not in range [0, " + Integer.MAX_VALUE + "]");
    }
    return (int) len;

  }

  /**
   * Reads a single byte value in CBOR format.
   *
   * @return the read byte value.
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected byte readSimpleValue() throws CodecException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, ONE_BYTE);
    return (byte) readUInt8();
  }

  /**
   * Reads a semantic tag value in CBOR format.
   *
   * @return the read tag value.
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected long readTag() throws CodecException {
    return readUInt(readMajorType(TYPE_TAG), false /* breakAllowed */);
  }

  /**
   * Prolog to reading an UTF-8 encoded string value in CBOR format.
   *
   * @return the length of the string to read, or -1 in case of infinite-length
   *         strings.
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected long readTextStringLength() throws CodecException {
    return readMajorTypeWithSize(TYPE_TEXT_STRING);
  }

  /**
   * Reads the next major type from the underlying input stream, and verifies
   * whether it matches the given expectation.
   *
   * @param majorType the expected major type, cannot be <code>null</code>
   *                 (unchecked).
   * @return the read subtype, or payload, of the read major type.
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected int readMajorType(int majorType) throws CodecException {
    int ib = is.read();
    if (majorType != ((ib >>> 5) & 0x07)) {
      fail("Unexpected type: %s, expected: %s!", CborType.getName(ib),
          CborType.getName(majorType));
    }
    return ib & 0x1F;
  }

  /**
   * Reads the next major type from the underlying input stream, and verifies
   * whether it matches the given expectations.
   *
   * @param majorType the expected major type, cannot be <code>null</code>
   *                 (unchecked);
   * @param subtype the expected subtype.
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected void readMajorTypeExact(int majorType, int subtype)
      throws CodecException {
    int st = readMajorType(majorType);
    if ((st ^ subtype) != 0) {
      fail("Unexpected subtype: %d, expected: %d!", st, subtype);
    }
  }

  /**
   * Reads the next major type from the underlying input stream, verifies
   * whether it matches the given expectation, and decodes the payload into a
   * size.
   *
   * @param majorType the expected major type, cannot be
   *                  <code>null</code> (unchecked).
   * @return the number of succeeding bytes, &gt;= 0, or -1 if an
   *         infinite-length type is read.
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected long readMajorTypeWithSize(int majorType)
      throws CodecException {
    return readUInt(readMajorType(majorType), true /* breakAllowed */);
  }

  /**
   * Reads an unsigned integer with a given length-indicator.
   *
   * @param length the length indicator to use;
   * @param breakAllowed whether break is allowed.
   * @return the read unsigned integer, as long value.
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected long readUInt(int length, boolean breakAllowed)
      throws CodecException {
    return readUInt(length, breakAllowed, false);
  }

  protected long readUInt(int length, boolean breakAllowed, boolean allow64Bit)
    throws CodecException {
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
   * @return value the read value, values from {@link Long#MIN_VALUE} to
   *         {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded
   *         value to the underlying output stream.
   */
  protected int readUInt16() throws CodecException {
    byte[] buf = readFully(new byte[2]);
    return (buf[0] & 0xFF) << 8 | (buf[1] & 0xFF);
  }

  /**
   * Reads an unsigned 32-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to
   *         {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded
   *         value to the underlying output stream.
   */
  protected long readUInt32() throws CodecException {
    byte[] buf = readFully(new byte[4]);
    return ((buf[0] & 0xFFL) << 24 | (buf[1] & 0xFF) << 16 |
            (buf[2] & 0xFF) << 8 | (buf[3] & 0xFF)) & 0xffffffffL;
  }

  /**
   * Reads an unsigned 64-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to
   *         {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded
   *         value to the underlying output stream.
   */
  protected long readUInt64() throws CodecException {
    byte[] buf = readFully(new byte[8]);
    return (buf[0] & 0xFFL) << 56 | (buf[1] & 0xFFL) << 48 |
           (buf[2] & 0xFFL) << 40 | (buf[3] & 0xFFL) << 32 |
           (buf[4] & 0xFFL) << 24 | (buf[5] & 0xFFL) << 16 |
           (buf[6] & 0xFFL) << 8  | (buf[7] & 0xFFL);
  }

  /**
   * Reads a <code>null</code>-value in CBOR format.
   * @throws CodecException in case of CBOR decoding problem or I/O problems
   *         reading the CBOR-encoded value from the underlying input stream.
   */
  public void readNull() throws CodecException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, NULL);
  }

  public void readUndefined() throws CodecException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, UNDEFINED);
  }

  public boolean readBoolean() throws CodecException {
    int b = readMajorType(TYPE_FLOAT_SIMPLE);
    if (b != FALSE && b != TRUE) {
      fail("Unexpected boolean value: %d!", b);
    }
    return b == TRUE;
  }

  public int readInt() throws CodecException {
    long v = readLong();
    if (v < Integer.MIN_VALUE || v > Integer.MAX_VALUE) {
      throw new CodecException("value is out of range of int32");
    }
    return (int) v;
  }

  public long readLong() throws CodecException {
    int ib = read1Byte();

    // in case of negative integers, extends the sign to all bits; otherwise
    // zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return ui ^ readUInt(ib & 0x1f, false /* breakAllowed */);
  }

  /**
   * Reads an unsigned 8-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to
   *         {@link Long#MAX_VALUE} are supported.
   * @throws CodecException in case of I/O problems writing the CBOR-encoded
   *         value to the underlying output stream.
   */
  protected int readUInt8() throws CodecException {
    return is.read() & 0xff;
  }

  protected int readInt8() throws CodecException {
    int ib = is.read();

    // in case of negative integers, extends the sign to all bits; otherwise
    // zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does an ones complement
    return (int) (ui ^ readUIntExact(ONE_BYTE, ib & 0x1f));
  }

  protected int readInt16() throws CodecException {
    int ib = is.read();

    // in case of negative integers, extends the sign to all bits; otherwise
    // zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return (int) (ui ^ readUIntExact(TWO_BYTES, ib & 0x1f));
  }

  protected long readInt32() throws CodecException {
    int ib = is.read();

    // in case of negative integers, extends the sign to all bits; otherwise
    // zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return ui ^ readUIntExact(FOUR_BYTES, ib & 0x1f);
  }

  protected long readInt64() throws CodecException {
    int ib = is.read();

    // in case of negative integers, extends the sign to all bits; otherwise
    // zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return ui ^ readUIntExact(EIGHT_BYTES, ib & 0x1f);
  }

  protected byte[] readFully(int size) throws CodecException {
    byte[] ret = new byte[size];
    return readFully(ret);
  }

  protected byte[] readFully(byte[] buf) throws CodecException {
    int len = buf.length;
    int n = 0, off = 0;
    while (n < len) {
      int count = is.read(buf, off + n, len - n);
      if (count < 0) {
        throw new CodecException("reach EOF");
      }
      n += count;
    }
    return buf;
  }

  protected boolean skipBreak() throws CodecException {
    CborType type = peekType();
    if (type.majorType() == TYPE_FLOAT_SIMPLE
        && type.additionalInfo() == BREAK) {
      readBreak();
      return true;
    } else {
      return false;
    }
  }

  protected long expectIntegerType(int ib) throws CodecException {
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
   * @throws CodecException in case of CBOR decoding problem.
   */
  protected long readUIntExact(int expectedLength, int length)
      throws CodecException {
    if ((expectedLength == -1 && length >= ONE_BYTE)
        || (expectedLength >= 0 && length != expectedLength)) {
      fail("Unexpected payload/length! Expected %s, but got %s.",
          CborDecoder.lengthToString(expectedLength),
          CborDecoder.lengthToString(length));
    }
    return readUInt(length, false /* breakAllowed */, true);
  }

  protected String concat(String prefix, String text) {
    if (prefix == null || prefix.isEmpty()) {
      return text;
    } else if (prefix.charAt(prefix.length() - 1) == '=') {
      return prefix + text;
    } else {
      return prefix + "=" + text;
    }
  }

}
