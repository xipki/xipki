/*
 * #THIRDPARTY#
 * JACOB - CBOR implementation in Java.
 * 
 * (C) Copyright - 2013 - J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package org.xipki.ca.sdk.jacob;

import org.xipki.ca.sdk.DecodeException;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.math.BigInteger;

/**
 * Provides a decoder capable of handling CBOR encoded data from a {@link InputStream}.
 */
public class CborDecoder implements AutoCloseable {
    protected final PushbackInputStream m_is;

    /**
     * Creates a new {@link CborDecoder} instance.
     * 
     * @param is the actual input stream to read the CBOR-encoded data from, cannot be <code>null</code>.
     */
    public CborDecoder(InputStream is) {
        if (is == null) {
            throw new IllegalArgumentException("InputStream cannot be null!");
        }
        m_is = (is instanceof PushbackInputStream) ? (PushbackInputStream) is : new PushbackInputStream(is);
    }

    private static void fail(String msg, Object... args) throws IOException {
        throw new IOException(String.format(msg, args));
    }

    private static String lengthToString(int len) {
        return (len < 0) ? "no payload" : (len == CborConstants.ONE_BYTE) ? "one byte" : (len == CborConstants.TWO_BYTES) ? "two bytes"
            : (len == CborConstants.FOUR_BYTES) ? "four bytes" : (len == CborConstants.EIGHT_BYTES) ? "eight bytes" : "(unknown)";
    }

    /**
     * Peeks in the input stream for the upcoming type.
     * 
     * @return the upcoming type in the stream, or <code>null</code> in case of an end-of-stream.
     * @throws IOException in case of I/O problems reading the CBOR-type from the underlying input stream.
     */
    public CborType peekType() throws IOException {
        int p = m_is.read();
        if (p < 0) {
            // EOF, nothing to peek at...
            return null;
        }
        m_is.unread(p);
        return CborType.valueOf(p);
    }

    /**
     * read one bye
     */
    public int read1Byte() throws IOException {
        return m_is.read();
    }

    /**
     * Prolog to reading an array value in CBOR format.
     * 
     * @return the number of elements in the array to read, or -1 in case of infinite-length arrays.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public long readArrayLength() throws IOException {
        return readMajorTypeWithSize(CborConstants.TYPE_ARRAY);
    }

    /**
     * Reads a boolean value in CBOR format.
     * 
     * @return the read boolean.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public boolean readBoolean() throws IOException {
        int b = readMajorType(CborConstants.TYPE_FLOAT_SIMPLE);
        if (b != CborConstants.FALSE && b != CborConstants.TRUE) {
            fail("Unexpected boolean value: %d!", b);
        }
        return b == CborConstants.TRUE;
    }

    /**
     * Reads a "break"/stop value in CBOR format.
     * 
     * @return always <code>null</code>.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public Object readBreak() throws IOException {
        readMajorTypeExact(CborConstants.TYPE_FLOAT_SIMPLE, CborConstants.BREAK);

        return null;
    }

    /**
     * Reads a byte string value in CBOR format.
     * 
     * @return the read byte string, or <code>null</code>.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public byte[] readByteString() throws IOException {
        CborType type = peekType();
        if (isNull(type)) {
            read1Byte();
            return null;
        }

        long len = readMajorTypeWithSize(CborConstants.TYPE_BYTE_STRING);
        if (len < 0) {
            fail("Infinite-length byte strings not supported!");
        }
        if (len > Integer.MAX_VALUE) {
            fail("String length too long!");
        }
        return readFully(new byte[(int) len]);
    }

    /**
     * Prolog to reading a byte string value in CBOR format.
     * 
     * @return the number of bytes in the string to read, or -1 in case of infinite-length strings.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public long readByteStringLength() throws IOException {
        return readMajorTypeWithSize(CborConstants.TYPE_BYTE_STRING);
    }

    /**
     * Reads a double-precision float value in CBOR format.
     * 
     * @return the read double value, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public double readDouble() throws IOException {
        readMajorTypeExact(CborConstants.TYPE_FLOAT_SIMPLE, CborConstants.DOUBLE_PRECISION_FLOAT);

        return Double.longBitsToDouble(readUInt64());
    }

    /**
     * Reads a single-precision float value in CBOR format.
     * 
     * @return the read float value, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public float readFloat() throws IOException {
        readMajorTypeExact(CborConstants.TYPE_FLOAT_SIMPLE, CborConstants.SINGLE_PRECISION_FLOAT);

        return Float.intBitsToFloat((int) readUInt32());
    }

    /**
     * Reads a half-precision float value in CBOR format.
     * 
     * @return the read half-precision float value, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public double readHalfPrecisionFloat() throws IOException {
        readMajorTypeExact(CborConstants.TYPE_FLOAT_SIMPLE, CborConstants.HALF_PRECISION_FLOAT);

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
     * Reads a signed or unsigned integer value in CBOR format.
     * 
     * @return the read integer value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public long readInt() throws IOException {
        int ib = m_is.read();

        // in case of negative integers, extends the sign to all bits; otherwise zero...
        long ui = expectIntegerType(ib);
        // in case of negative integers does a ones complement
        return ui ^ readUInt(ib & 0x1f, false /* breakAllowed */);
    }

    /**
     * Reads a signed or unsigned 16-bit integer value in CBOR format.
     * 
     * read the small integer value, values from [-65536..65535] are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
     */
    public int readInt16() throws IOException {
        int ib = m_is.read();

        // in case of negative integers, extends the sign to all bits; otherwise zero...
        long ui = expectIntegerType(ib);
        // in case of negative integers does a ones complement
        return (int) (ui ^ readUIntExact(CborConstants.TWO_BYTES, ib & 0x1f));
    }

    /**
     * Reads a signed or unsigned 32-bit integer value in CBOR format.
     * 
     * read the small integer value, values in the range [-4294967296..4294967295] are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
     */
    public long readInt32() throws IOException {
        int ib = m_is.read();

        // in case of negative integers, extends the sign to all bits; otherwise zero...
        long ui = expectIntegerType(ib);
        // in case of negative integers does a ones complement
        return ui ^ readUIntExact(CborConstants.FOUR_BYTES, ib & 0x1f);
    }

    /**
     * Reads a signed or unsigned 64-bit integer value in CBOR format.
     * 
     * read the small integer value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
     */
    public long readInt64() throws IOException {
        int ib = m_is.read();

        // in case of negative integers, extends the sign to all bits; otherwise zero...
        long ui = expectIntegerType(ib);
        // in case of negative integers does a ones complement
        return ui ^ readUIntExact(CborConstants.EIGHT_BYTES, ib & 0x1f);
    }

    /**
     * Reads a signed or unsigned 8-bit integer value in CBOR format.
     * 
     * read the small integer value, values in the range [-256..255] are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
     */
    public int readInt8() throws IOException {
        int ib = m_is.read();

        // in case of negative integers, extends the sign to all bits; otherwise zero...
        long ui = expectIntegerType(ib);
        // in case of negative integers does a ones complement
        return (int) (ui ^ readUIntExact(CborConstants.ONE_BYTE, ib & 0x1f));
    }

    /**
     * Prolog to reading a map of key-value pairs in CBOR format.
     * 
     * @return the number of entries in the map, &gt;= 0.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public long readMapLength() throws IOException {
        return readMajorTypeWithSize(CborConstants.TYPE_MAP);
    }

    /**
     * Reads a <code>null</code>-value in CBOR format.
     * 
     * @return always <code>null</code>.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public Object readNull() throws IOException {
        readMajorTypeExact(CborConstants.TYPE_FLOAT_SIMPLE, CborConstants.NULL);
        return null;
    }

    /**
     * Reads a single byte value in CBOR format.
     * 
     * @return the read byte value.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public byte readSimpleValue() throws IOException {
        readMajorTypeExact(CborConstants.TYPE_FLOAT_SIMPLE, CborConstants.ONE_BYTE);
        return (byte) readUInt8();
    }

    /**
     * Reads a signed or unsigned small (&lt;= 23) integer value in CBOR format.
     * 
     * read the small integer value, values in the range [-24..23] are supported.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
     */
    public int readSmallInt() throws IOException {
        int ib = m_is.read();

        // in case of negative integers, extends the sign to all bits; otherwise zero...
        long ui = expectIntegerType(ib);
        // in case of negative integers does a ones complement
        return (int) (ui ^ readUIntExact(-1, ib & 0x1f));
    }

    /**
     * Reads a semantic tag value in CBOR format.
     * 
     * @return the read tag value.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public long readTag() throws IOException {
        return readUInt(readMajorType(CborConstants.TYPE_TAG), false /* breakAllowed */);
    }

    /**
     * Reads an UTF-8 encoded string value in CBOR format.
     * 
     * @return the read UTF-8 encoded string, or <code>null</code>.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public String readTextString() throws IOException {
        CborType type = peekType();
        if (isNull(type)) {
            read1Byte();
            return null;
        }

        long len = readMajorTypeWithSize(CborConstants.TYPE_TEXT_STRING);
        if (len < 0) {
            fail("Infinite-length text strings not supported!");
        }
        if (len > Integer.MAX_VALUE) {
            fail("String length too long!");
        }
        return new String(readFully(new byte[(int) len]), "UTF-8");
    }

    /**
     * Prolog to reading an UTF-8 encoded string value in CBOR format.
     * 
     * @return the length of the string to read, or -1 in case of infinite-length strings.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public long readTextStringLength() throws IOException {
        return readMajorTypeWithSize(CborConstants.TYPE_TEXT_STRING);
    }

    /**
     * Reads an undefined value in CBOR format.
     * 
     * @return always <code>null</code>.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    public Object readUndefined() throws IOException {
        readMajorTypeExact(CborConstants.TYPE_FLOAT_SIMPLE, CborConstants.UNDEFINED);
        return null;
    }

    /**
     * Reads the next major type from the underlying input stream, and verifies whether it matches the given expectation.
     * 
     * @param ib the expected major type, cannot be <code>null</code> (unchecked).
     * @return either -1 if the major type was an signed integer, or 0 otherwise.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    protected long expectIntegerType(int ib) throws IOException {
        int majorType = ((ib & 0xFF) >>> 5);
        if ((majorType != CborConstants.TYPE_UNSIGNED_INTEGER) && (majorType != CborConstants.TYPE_NEGATIVE_INTEGER)) {
            fail("Unexpected type: %s, expected type %s or %s!", CborType.getName(majorType), CborType.getName(CborConstants.TYPE_UNSIGNED_INTEGER),
                CborType.getName(CborConstants.TYPE_NEGATIVE_INTEGER));
        }
        return -majorType;
    }

    /**
     * Reads the next major type from the underlying input stream, and verifies whether it matches the given expectation.
     * 
     * @param majorType the expected major type, cannot be <code>null</code> (unchecked).
     * @return the read subtype, or payload, of the read major type.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    protected int readMajorType(int majorType) throws IOException {
        int ib = m_is.read();
        if (majorType != ((ib >>> 5) & 0x07)) {
            fail("Unexpected type: %s, expected: %s!", CborType.getName(ib), CborType.getName(majorType));
        }
        return ib & 0x1F;
    }

    /**
     * Reads the next major type from the underlying input stream, and verifies whether it matches the given expectations.
     * 
     * @param majorType the expected major type, cannot be <code>null</code> (unchecked);
     * @param subtype the expected subtype.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    protected void readMajorTypeExact(int majorType, int subtype) throws IOException {
        int st = readMajorType(majorType);
        if ((st ^ subtype) != 0) {
            fail("Unexpected subtype: %d, expected: %d!", st, subtype);
        }
    }

    /**
     * Reads the next major type from the underlying input stream, verifies whether it matches the given expectation, and decodes the payload into a size.
     * 
     * @param majorType the expected major type, cannot be <code>null</code> (unchecked).
     * @return the number of succeeding bytes, &gt;= 0, or -1 if an infinite-length type is read.
     * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
     */
    protected long readMajorTypeWithSize(int majorType) throws IOException {
        return readUInt(readMajorType(majorType), true /* breakAllowed */);
    }

    /**
     * Reads an unsigned integer with a given length-indicator.
     * 
     * @param length the length indicator to use;
     * @return the read unsigned integer, as long value.
     * @throws IOException in case of I/O problems reading the unsigned integer from the underlying input stream.
     */
    protected long readUInt(int length, boolean breakAllowed) throws IOException {
        long result = -1;
        if (length < CborConstants.ONE_BYTE) {
            result = length;
        } else if (length == CborConstants.ONE_BYTE) {
            result = readUInt8();
        } else if (length == CborConstants.TWO_BYTES) {
            result = readUInt16();
        } else if (length == CborConstants.FOUR_BYTES) {
            result = readUInt32();
        } else if (length == CborConstants.EIGHT_BYTES) {
            result = readUInt64();
        } else if (breakAllowed && length == CborConstants.BREAK) {
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
    protected int readUInt16() throws IOException {
        byte[] buf = readFully(new byte[2]);
        return (buf[0] & 0xFF) << 8 | (buf[1] & 0xFF);
    }

    /**
     * Reads an unsigned 32-bit integer value
     * 
     * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    protected long readUInt32() throws IOException {
        byte[] buf = readFully(new byte[4]);
        return ((buf[0] & 0xFF) << 24 | (buf[1] & 0xFF) << 16 | (buf[2] & 0xFF) << 8 | (buf[3] & 0xFF)) & 0xffffffffL;
    }

    /**
     * Reads an unsigned 64-bit integer value
     * 
     * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    protected long readUInt64() throws IOException {
        byte[] buf = readFully(new byte[8]);
        return (buf[0] & 0xFFL) << 56 | (buf[1] & 0xFFL) << 48 | (buf[2] & 0xFFL) << 40 | (buf[3] & 0xFFL) << 32 | //
            (buf[4] & 0xFFL) << 24 | (buf[5] & 0xFFL) << 16 | (buf[6] & 0xFFL) << 8 | (buf[7] & 0xFFL);
    }

    /**
     * Reads an unsigned 8-bit integer value
     * 
     * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
     * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
     */
    protected int readUInt8() throws IOException {
        return m_is.read() & 0xff;
    }

    /**
     * Reads an unsigned integer with a given length-indicator.
     * 
     * @param length the length indicator to use;
     * @return the read unsigned integer, as long value.
     * @throws IOException in case of I/O problems reading the unsigned integer from the underlying input stream.
     */
    protected long readUIntExact(int expectedLength, int length) throws IOException {
        if (((expectedLength == -1) && (length >= CborConstants.ONE_BYTE)) || ((expectedLength >= 0) && (length != expectedLength))) {
            fail("Unexpected payload/length! Expected %s, but got %s.", lengthToString(expectedLength),
                lengthToString(length));
        }
        return readUInt(length, false /* breakAllowed */);
    }

    private byte[] readFully(byte[] buf) throws IOException {
        int len = buf.length;
        int n = 0, off = 0;
        while (n < len) {
            int count = m_is.read(buf, off + n, len - n);
            if (count < 0) {
                throw new EOFException();
            }
            n += count;
        }
        return buf;
    }

    // added by Lijun Liao

    /**
     * true if it is null, or false it is an array of the specified length.
     * @param expectedLen the expected length of an array.
     * @return whether it is null.
     * @throws IOException if cannot decode the stream or is not an array with given length.
     */
    public boolean readNullOrArrayLength(int expectedLen) throws IOException {
        Integer len = readNullOrArrayLength();
        if (len == null) {
            return true;
        } else if (len != expectedLen) {
            throw new IOException("stream has an array but the length != " + expectedLen +": " + len);
        } else {
            return false;
        }
    }

    public Integer readNullOrArrayLength() throws IOException {
        CborType type = peekType();
        if (isNull(type)) {
            read1Byte();
            return null;
        } else if (type.getMajorType() == CborConstants.TYPE_ARRAY) {
            return (int) readArrayLength();
        } else {
            throw new IOException("stream does not have an array");
        }
    }

    public Integer readNullOrArrayLength(Class clazz) throws DecodeException {
        try {
            return readNullOrArrayLength();
        } catch (IOException ex) {
            throw new DecodeException("error decoding " + clazz.getName(), ex);
        }
    }

    public static boolean isNull(CborType type) {
        return type.getMajorType() == CborConstants.TYPE_FLOAT_SIMPLE
            && type.getAdditionalInfo() == CborConstants.NULL;
    }

    public Boolean readBooleanObj() throws IOException {
        CborType type = peekType();
        if (isNull(type)) {
            read1Byte();
            return null;
        } else if (type.getMajorType() == CborConstants.TYPE_FLOAT_SIMPLE) {
            return readBoolean();
        } else {
            throw new IOException("stream does not have integer");
        }
    }

    public Long readIntObj() throws IOException {
        CborType type = peekType();
        if (isNull(type)) {
            read1Byte();
            return null;
        } else if (type.getMajorType() == CborConstants.TYPE_UNSIGNED_INTEGER
            || type.getMajorType() == CborConstants.TYPE_NEGATIVE_INTEGER) {
            return readInt();
        } else {
            throw new IOException("stream does not have integer");
        }
    }

    public Integer readInt32Obj() throws IOException {
        CborType type = peekType();
        if (isNull(type)) {
            read1Byte();
            return null;
        } else if (type.getMajorType() == CborConstants.TYPE_UNSIGNED_INTEGER
            || type.getMajorType() == CborConstants.TYPE_NEGATIVE_INTEGER) {
            return readInt32Exact();
        } else {
            throw new IOException("stream does not have integer");
        }
    }

    public BigInteger readBigInt() throws IOException {
        byte[] bytes = readByteString();
        return bytes == null ? null : new BigInteger(bytes);
    }

    public String[] readTextStrings() throws IOException {
        Integer arrayLen = readNullOrArrayLength();
        if (arrayLen == null) {
            return null;
        }

        String[] ret = new String[arrayLen];
        for (int i = 0; i < arrayLen; i++) {
            ret[i] = readTextString();
        }

        return ret;
    }

    public byte[][] readByteStrings() throws IOException {
        Integer arrayLen = readNullOrArrayLength();
        if (arrayLen == null) {
            return null;
        }

        byte[][] ret = new byte[arrayLen][];
        for (int i = 0; i < arrayLen; i++) {
            ret[i] = readByteString();
        }

        return ret;
    }

    public BigInteger[] readBigInts() throws IOException {
        byte[][] bytes = readByteStrings();
        if (bytes == null) {
            return null;
        }

        BigInteger[] ret = new BigInteger[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            ret[i] = bytes[i] == null ? null : new BigInteger(bytes[i]);
        }

        return ret;
    }

    public int readInt32Exact() throws IOException {
        long v = readInt();
        if (v < Integer.MIN_VALUE || v > Integer.MAX_VALUE) {
            throw new IOException("value is out of range of int32");
        }
        return (int) v;
    }


    @Override
    public void close() throws IOException {
        m_is.close();
    }
}
