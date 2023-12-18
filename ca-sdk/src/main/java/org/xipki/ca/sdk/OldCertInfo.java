// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.util.Args;
import org.xipki.util.cbor.*;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;
import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class OldCertInfo extends SdkEncodable {

  /**
   * Whether to reu-use the public key in the old certificate for the new one.
   */
  private final boolean reusePublicKey;

  private final ByIssuerAndSerial isn;

  private final BySubject subject;

  public OldCertInfo(boolean reusePublicKey, ByIssuerAndSerial isn) {
    this.reusePublicKey = reusePublicKey;
    this.isn = Args.notNull(isn, "isn");
    this.subject = null;
  }

  public OldCertInfo(boolean reusePublicKey, BySubject subject) {
    this.reusePublicKey = reusePublicKey;
    this.isn = null;
    this.subject = Args.notNull(subject, "subject");
  }

  public boolean isReusePublicKey() {
    return reusePublicKey;
  }

  public ByIssuerAndSerial getIsn() {
    return isn;
  }

  public BySubject getSubject() {
    return subject;
  }

  @Override
  protected void encode0(CborEncoder encoder) throws IOException, EncodeException {
    encoder.writeArrayStart(3);
    encoder.writeBoolean(isReusePublicKey());
    encoder.writeObject(isn);
    encoder.writeObject(subject);
  }

  public static OldCertInfo decode(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(3)) {
        return null;
      }

      boolean usePublicKey = decoder.readBoolean();
      ByIssuerAndSerial isn = ByIssuerAndSerial.decode(decoder);
      BySubject subject = BySubject.decode(decoder);

      if ((isn == null) == (subject == null)) {
        throw new DecodeException("exactly one of isn and subject shall be non-null");
      }

      if (isn != null) {
        return new OldCertInfo(usePublicKey, isn);
      } else {
        return new OldCertInfo(usePublicKey, subject);
      }
    } catch (IOException | RuntimeException ex) {
      throw new DecodeException(buildDecodeErrMessage(ex, ByIssuerAndSerial.class), ex);
    }
  }

  public static class ByIssuerAndSerial extends SdkEncodable {

    private final X500NameType issuer;

    /**
     * Uppercase hex encoded serialNumber.
     */
    private final BigInteger serialNumber;

    public ByIssuerAndSerial(X500NameType issuer, BigInteger serialNumber) {
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
      encoder.writeArrayStart(2);
      encoder.writeObject(issuer);
      encoder.writeBigInt(serialNumber);
    }

    public static ByIssuerAndSerial decode(CborDecoder decoder) throws DecodeException {
      try {
        if (decoder.readNullOrArrayLength(2)) {
          return null;
        }

        return new ByIssuerAndSerial(
            X500NameType.decode(decoder),
            decoder.readBigInt());
      } catch (IOException | RuntimeException ex) {
        throw new DecodeException(buildDecodeErrMessage(ex, ByIssuerAndSerial.class), ex);
      }
    }
  }

  public static class BySubject extends SdkEncodable {

    private final byte[] subject;

    private final byte[] san;

    public BySubject(byte[] subject, byte[] san) {
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
      encoder.writeArrayStart(2);
      encoder.writeByteString(subject);
      encoder.writeByteString(san);
    }

    public static BySubject decode(CborDecoder decoder) throws DecodeException {
      try {
        if (decoder.readNullOrArrayLength(2)) {
          return null;
        }

        return new BySubject(
            decoder.readByteString(),
            decoder.readByteString());
      } catch (IOException | RuntimeException ex) {
        throw new DecodeException(buildDecodeErrMessage(ex, BySubject.class), ex);
      }
    }

  }
}
