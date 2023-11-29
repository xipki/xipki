// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;
import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public abstract class OldCertInfo extends SdkEncodable {

  /**
   * Whether to reu-use the public key in the old certificate for the new one.
   */
  private final boolean reusePublicKey;

  public OldCertInfo(boolean reusePublicKey) {
    this.reusePublicKey = reusePublicKey;
  }

  public boolean isReusePublicKey() {
    return reusePublicKey;
  }

  public static class ByIssuerAndSerial extends OldCertInfo {

    private final X500NameType issuer;

    /**
     * Uppercase hex encoded serialNumber.
     */
    private final BigInteger serialNumber;

    public ByIssuerAndSerial(boolean reusePublicKey, X500NameType issuer, BigInteger serialNumber) {
      super(reusePublicKey);
      this.issuer = issuer;
      this.serialNumber = serialNumber;
    }

    public X500NameType getIssuer() {
      return issuer;
    }

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
      encoder.writeArrayStart(3);
      encoder.writeBoolean(isReusePublicKey());
      encoder.writeObject(issuer);
      encoder.writeBigInt(serialNumber);
    }

    public static ByIssuerAndSerial decode(CborDecoder decoder) throws DecodeException {
      try {
        if (decoder.readNullOrArrayLength(3)) {
          return null;
        }

        return new ByIssuerAndSerial(
            decoder.readBoolean(),
            X500NameType.decode(decoder),
            decoder.readBigInt());
      } catch (IOException | RuntimeException ex) {
        throw new DecodeException(buildDecodeErrMessage(ex, ByIssuerAndSerial.class), ex);
      }
    }

  }

  public static class BySubject extends OldCertInfo {

    private final byte[] subject;

    private final byte[] san;

    public BySubject(boolean reusePublicKey, byte[] subject, byte[] san) {
      super(reusePublicKey);
      this.subject = subject;
      this.san = san;
    }

    public byte[] getSubject() {
      return subject;
    }

    public byte[] getSan() {
      return san;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
      encoder.writeArrayStart(3);
      encoder.writeBoolean(isReusePublicKey());
      encoder.writeByteString(subject);
      encoder.writeByteString(san);
    }

    public static BySubject decode(CborDecoder decoder) throws DecodeException {
      try {
        if (decoder.readNullOrArrayLength(3)) {
          return null;
        }

        return new BySubject(
            decoder.readBoolean(),
            decoder.readByteString(),
            decoder.readByteString());
      } catch (IOException | RuntimeException ex) {
        throw new DecodeException(buildDecodeErrMessage(ex, BySubject.class), ex);
      }
    }

  }
}
