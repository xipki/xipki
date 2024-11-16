// #THIRDPARTY
/*
 * JACOB - CBOR implementation in Java.
 *
 * (C) Copyright - 2013 - J.W. Janssen <j.w.janssen@lxtreme.nl>
 *
 * Licensed under Apache License v2.0.
 */
package org.xipki.util.cbor;

import org.xipki.util.Args;
import org.xipki.util.exception.DecodeException;

import java.io.IOException;

import static org.xipki.util.cbor.CborConstants.*;
import static org.xipki.util.cbor.CborConstants.FALSE;
import static org.xipki.util.cbor.CborConstants.NULL;
import static org.xipki.util.cbor.CborConstants.TRUE;
import static org.xipki.util.cbor.CborConstants.TYPE_ARRAY;
import static org.xipki.util.cbor.CborConstants.TYPE_BYTE_STRING;
import static org.xipki.util.cbor.CborConstants.TYPE_FLOAT_SIMPLE;
import static org.xipki.util.cbor.CborConstants.TYPE_MAP;
import static org.xipki.util.cbor.CborConstants.TYPE_NEGATIVE_INTEGER;
import static org.xipki.util.cbor.CborConstants.TYPE_TAG;
import static org.xipki.util.cbor.CborConstants.TYPE_TEXT_STRING;
import static org.xipki.util.cbor.CborConstants.TYPE_UNSIGNED_INTEGER;

/**
 * Represents the various major types in CBOR, along with their .
 * <p>
 * The major type is encoded in the upper three bits of each initial byte. The lower 5 bytes represent any additional information.
 * </p>
 */
public class CborType {
  private final int m_major;
  private final int m_additional;

  private CborType(int major, int additional) {
        m_major = major;
        m_additional = additional;
  }

  /**
     * Returns a descriptive string for the given major type.
     *
     * @param mt the major type to return as string, values from [0..7] are supported.
     * @return the name of the given major type, as String, never <code>null</code>.
     * @throws IllegalArgumentException in case the given major type is not supported.
     */
  public static String getName(int mt) {
        switch (mt) {
            case TYPE_ARRAY:
                return "array";
            case TYPE_BYTE_STRING:
                return "byte string";
            case TYPE_FLOAT_SIMPLE:
                return "float/simple value";
            case TYPE_MAP:
                return "map";
            case TYPE_NEGATIVE_INTEGER:
                return "negative integer";
            case TYPE_TAG:
                return "tag";
            case TYPE_TEXT_STRING:
                return "text string";
            case TYPE_UNSIGNED_INTEGER:
                return "unsigned integer";
            default:
                throw new IllegalArgumentException("Invalid major type: " + mt);
        }
  }

  /**
     * Decodes a given byte value to a {@link CborType} value.
     *
     * @param i the input byte (8-bit) to decode into a {@link CborType} instance.
     * @return a {@link CborType} instance, never <code>null</code>.
     */
  public static CborType valueOf(int i) {
        return new CborType((i & 0xff) >>> 5, i & 0x1f);
  }

  @Override
  public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }

        CborType other = (CborType) obj;
        return (m_major == other.m_major) && (m_additional == other.m_additional);
  }

  /**
     * @return the additional information of this type, as integer value from [0..31].
     */
  public int getAdditionalInfo() {
        return m_additional;
  }

  /**
     * @return the major type, as integer value from [0..7].
     */
  public int getMajorType() {
        return m_major;
  }

  public boolean isBooleanType() {
        return m_major == TYPE_FLOAT_SIMPLE &&
            (m_additional == TRUE || m_additional == FALSE);
  }

  public boolean isArray() {
        return m_major == TYPE_ARRAY;
  }

  public boolean isMap() {
        return m_major == TYPE_MAP;
  }

  public boolean isInt() {
        return m_major == TYPE_UNSIGNED_INTEGER
            || m_major == TYPE_NEGATIVE_INTEGER;
  }

  public boolean isUint() {
        return m_major == TYPE_UNSIGNED_INTEGER;
  }

  public boolean isTextString() {
        return m_major == TYPE_TEXT_STRING;
  }

  public boolean isByteString() {
        return m_major == TYPE_BYTE_STRING;
  }

  public boolean isNull() {
        return m_major == TYPE_FLOAT_SIMPLE &&
            m_additional == NULL;
  }

  public boolean isNullThenRead(CborDecoder decoder)
        throws DecodeException {
        boolean isNull = (m_major == TYPE_FLOAT_SIMPLE &&
            m_additional == NULL);
        if (isNull) {
            decoder.readNull();
        }
        return isNull;
  }

  public boolean isTag() {
        return m_major == TYPE_TAG;
  }

  @Override
  public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + m_additional;
        result = prime * result + m_major;
        return result;
  }

  /**
     * @return <code>true</code> if this type allows for an infinite-length payload,
     *         <code>false</code> if only definite-length payloads are allowed.
     */
  public boolean isBreakAllowed() {
        return m_major == TYPE_ARRAY
            || m_major == TYPE_BYTE_STRING
            || m_major == TYPE_MAP
            || m_major == TYPE_TEXT_STRING;
  }

  /**
     * Determines whether the major type of the given {@link CborType} equals the major type of this {@link CborType}.
     *
     * @param other the {@link CborType} to compare against, cannot be <code>null</code>.
     * @return <code>true</code> if the given {@link CborType} is of the same major type as this {@link CborType},
     *         <code>false</code> otherwise.
     * @throws IllegalArgumentException in case the given argument was <code>null</code>.
     */
  public boolean isEqualType(CborType other) {
        return m_major == Args.notNull(other, "other").m_major;
  }

  /**
     * Determines whether the major type of the given byte value (representing an encoded {@link CborType}) equals the major type of this {@link CborType}.
     *
     * @param encoded the encoded CBOR type to compare.
     * @return <code>true</code> if the given byte value represents the same major type as this {@link CborType}, <code>false</code> otherwise.
     */
  public boolean isEqualType(int encoded) {
        return m_major == ((encoded & 0xff) >>> 5);
  }

  @Override
  public String toString() {
        return getName(m_major) + '(' + m_additional + ')';
  }
}
