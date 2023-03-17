// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.type;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.server.type.OcspRequest.Header;
import org.xipki.util.CompareUtil;
import org.xipki.util.Hex;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;

/**
 * ASN.1 extension that can be read and written.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class ExtendedExtension extends Extension {

  private static final Logger LOG = LoggerFactory.getLogger(ExtendedExtension.class);

  private static final byte[] bytes_critical = Hex.decode("0101FF");

  private final OID extnType;

  private final byte[] encoded;

  private final int from;

  private final boolean critical;

  private final int encodedLength;

  private final int extnValueFrom;

  private final int extnValueLength;

  public ExtendedExtension(OID extnType, boolean critical, byte[] extnValue) {
    int bodyLen = extnType.getEncodedLength();
    if (critical) {
      bodyLen += 3;
    }
    bodyLen += getLen(extnValue.length);

    this.extnType = extnType;
    this.critical = critical;
    encodedLength = getLen(bodyLen);
    extnValueLength = extnValue.length;
    extnValueFrom = encodedLength - extnValueLength;
    from = 0;
    encoded = new byte[encodedLength];

    int offset = writeHeader((byte) 0x30, bodyLen, encoded, 0);
    offset += extnType.write(encoded, offset);
    if (critical) {
      offset += arraycopy(bytes_critical, encoded, offset);
    }
    offset += writeHeader((byte) 0x04, extnValue.length, encoded, offset);
    arraycopy(extnValue, encoded, offset);
  }

  private ExtendedExtension(
      OID extnType, byte[] encoded, int from, boolean critical,
      int encodedLength, int extnValueFrom, int extnValueLength) {
    super();
    this.extnType = extnType;
    this.encoded = encoded;
    this.from = from;
    this.critical = critical;
    this.encodedLength = encodedLength;
    this.extnValueFrom = extnValueFrom;
    this.extnValueLength = extnValueLength;
  }

  public static ExtendedExtension getInstance(byte[] encoded, int from, int len)
      throws EncodingException {
    Header hdrExtn = OcspRequest.readHeader(encoded, from);
    Header hdrOid = OcspRequest.readHeader(encoded, hdrExtn.readerIndex);
    Header hdrNext = OcspRequest.readHeader(encoded, hdrOid.readerIndex + hdrOid.len);
    Header hdrExtValue;

    boolean critical;
    if (hdrNext.tag == 0x01) { // critical
      critical = encoded[hdrNext.readerIndex] == (byte) 0xFF;
      hdrExtValue = OcspRequest.readHeader(encoded, hdrNext.readerIndex + hdrNext.len);
    } else {
      critical = false;
      hdrExtValue = hdrNext;
    }

    OID extnType = OID.getInstanceForEncoded(encoded, hdrOid.tagIndex);
    if (extnType == null) {
      byte[] bytes = new byte[hdrOid.readerIndex - hdrOid.tagIndex + hdrOid.len];
      System.arraycopy(encoded, hdrOid.tagIndex, bytes, 0, bytes.length);
      ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(bytes);
      LOG.warn("unknown extension {}", oid.getId());
      if (critical) {
        throw new EncodingException("unkown critical extension: " + oid.getId());
      } else {
        return null;
      }
    }

    int extnValueFrom = hdrExtValue.readerIndex;
    int extnValueLength = hdrExtValue.len;

    return new ExtendedExtension(extnType, encoded, from, critical, len,
        extnValueFrom, extnValueLength);
  }

  @Override
  public int getEncodedLength() {
    return encodedLength;
  }

  public static int getEncodedLength(OID extnType, boolean critical, int extnValueLength) {
    int bodyLen = extnType.getEncodedLength();
    if (critical) {
      bodyLen += 3;
    }
    bodyLen += getLen(extnValueLength);
    return getLen(bodyLen);
  }

  public boolean isCritical() {
    return critical;
  }

  public OID getExtnType() {
    return extnType;
  }

  public int getExtnValueLength() {
    return extnValueLength;
  }

  public InputStream getExtnValueStream() {
    return new ByteArrayInputStream(encoded, extnValueFrom, extnValueLength);
  }

  @Override
  public int write(byte[] out, int offset) {
    System.arraycopy(encoded, from, out, offset, encodedLength);
    return encodedLength;
  }

  public boolean equalsExtnValue(byte[] value) {
    if (value.length != extnValueLength) {
      return false;
    }
    return CompareUtil.areEqual(value, 0, encoded, extnValueFrom, extnValueLength);
  }

  public int writeExtnValue(byte[] out, int offset) {
    System.arraycopy(encoded, extnValueFrom, out, offset, extnValueLength);
    return extnValueLength;
  }

  public ExtendedExtension revertCritical() {
    byte[] extnValue = Arrays.copyOfRange(encoded, extnValueFrom, extnValueFrom + extnValueLength);
    return new ExtendedExtension(extnType, !critical, extnValue);
  }

}
