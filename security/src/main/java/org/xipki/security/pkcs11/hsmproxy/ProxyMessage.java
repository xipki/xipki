// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11.hsmproxy;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.pkcs11.wrapper.MechanismInfo;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.params.ExtraParams;
import org.xipki.security.pkcs11.P11Key;
import org.xipki.security.pkcs11.P11ModuleConf;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotId;
import org.xipki.util.Args;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborEncodable;
import org.xipki.util.cbor.CborEncoder;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The CBOR message.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class ProxyMessage implements CborEncodable {

  protected abstract void encode0(CborEncoder encoder) throws EncodeException, IOException;

  @Override
  public final void encode(CborEncoder encoder) throws EncodeException {
    try {
      encode0(encoder);
    } catch (IOException ex) {
      throw new EncodeException("IO error", ex);
    }
  }

  private static boolean isNotNullOrElseWriteNull(CborEncoder encoder, Object obj) throws IOException {
    if (obj == null) {
      encoder.writeNull();
      return false;
    }
    return true;
  }

  private static void writeBigInt(CborEncoder encoder, BigInteger value) throws IOException {
    if (isNotNullOrElseWriteNull(encoder, value)) {
      encoder.writeByteString(value.toByteArray());
    }
  }

  private static void writeOid(CborEncoder encoder, ASN1ObjectIdentifier value) throws IOException {
    if (isNotNullOrElseWriteNull(encoder, value)) {
      encoder.writeTextString(value.getId());
    }
  }

  private static ASN1ObjectIdentifier readOid(CborDecoder decoder) throws IOException, DecodeException {
    String text = decoder.readTextString();
    if (text == null) {
      return null;
    }

    try {
      return new ASN1ObjectIdentifier(text);
    } catch (IllegalArgumentException ex) {
      throw new DecodeException(text + " is not a valid ObjectIdentifier");
    }
  }

  private static void writeNewKeyControl(CborEncoder encoder, P11Slot.P11NewKeyControl control) throws IOException {
    if (control == null) {
      encoder.writeNull();
      return;
    }

    encoder.writeArrayStart(5);
    encoder.writeByteString(control.getId());
    encoder.writeTextString(control.getLabel());
    encoder.writeBooleanObj(control.getSensitive());
    encoder.writeBooleanObj(control.getExtractable());

    Set<P11Slot.P11KeyUsage> usages = control.getUsages();
    if (usages == null) {
      encoder.writeNull();
    } else {
      encoder.writeArrayStart(usages.size());
      for (P11Slot.P11KeyUsage usage: usages) {
        encoder.writeTextString(usage.name());
      }
    }
  }

  private static P11Slot.P11NewKeyControl decodeNewKeyControl(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(5)) {
        return null;
      }

      byte[] id = decoder.readByteString();
      String label = decoder.readTextString();
      P11Slot.P11NewKeyControl control = new P11Slot.P11NewKeyControl(id, label);
      control.setSensitive(decoder.readBooleanObj());
      control.setExtractable(decoder.readBooleanObj());

      // usages
      Integer usagesLen = decoder.readNullOrArrayLength();
      if (usagesLen != null) {
        Set<P11Slot.P11KeyUsage> usages = new HashSet<>(usagesLen * 5 / 4);
        for (int i = 0; i < usagesLen; i++) {
          String usageText = decoder.readTextString();
          P11Slot.P11KeyUsage usage;
          try {
            usage = P11Slot.P11KeyUsage.valueOf(usageText);
          } catch (IllegalArgumentException e) {
            throw new DecodeException("unknown P11KeyUsage " + usageText);
          }
          usages.add(usage);
        }

        control.setUsages(usages);
      }

      return control;
    } catch (IOException ex) {
      throw new DecodeException("IO error", ex);
    }
  }

  private static void writeKeyId(CborEncoder encoder, PKCS11KeyId keyId) throws IOException {
    encoder.writeArrayStart(6);
    encoder.writeInt(keyId.getHandle());
    encoder.writeInt(keyId.getObjectCLass());
    encoder.writeInt(keyId.getKeyType());
    encoder.writeByteString(keyId.getId());
    encoder.writeTextString(keyId.getLabel());
    encoder.writeIntObj(keyId.getPublicKeyHandle());
  }

  private static PKCS11KeyId decodeKeyId(CborDecoder decoder) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(6)) {
        return null;
      }

      long handle = decoder.readLong();
      long objectCLass = decoder.readLong();
      long keyType = decoder.readLong();
      byte[] id = decoder.readByteString();
      String label = decoder.readTextString();
      Long publicKeyHandle = decoder.readLongObj();

      PKCS11KeyId keyId = new PKCS11KeyId(handle, objectCLass, keyType, id, label);
      keyId.setPublicKeyHandle(publicKeyHandle);
      return keyId;
    } catch (IOException ex) {
      throw new DecodeException("IO error decoding PKCS11KeyId", ex);
    }
  }

  private static void assertArraySize(CborDecoder decoder, int arraySize, String name) throws DecodeException {
    try {
      if (decoder.readNullOrArrayLength(arraySize)) {
        throw new DecodeException(name + " shall not be null");
      }
    } catch (IOException ex) {
      throw new DecodeException("IO error reading arrayLength of " + name);
    }
  }

  /**
   * The message wrapper for boolean.
   */
  public static class BooleanMessage extends ProxyMessage {

    private final boolean value;

    public BooleanMessage(boolean value) {
      this.value = value;
    }

    public boolean getValue() {
      return value;
    }

    @Override
    public void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeBoolean(value);
    }

    public static BooleanMessage decode(CborDecoder decoder) throws DecodeException {
      try {
        boolean b = Optional.ofNullable(decoder.readBooleanObj()).orElseThrow(
            () -> new DecodeException("BooleanMessage shall not be null"));
        return new BooleanMessage(b);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding BooleanMessage", ex);
      }
    }

  }

  /**
   * The message wrapper for byte[].
   */
  public static class ByteArrayMessage extends ProxyMessage {

    private final byte[] value;

    public ByteArrayMessage(byte[] value) {
      this.value = Args.notNull(value, "value");
    }

    public byte[] getValue() {
      return value;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws IOException {
      encoder.writeByteString(value);
    }

    public static ByteArrayMessage decode(CborDecoder decoder) throws DecodeException {
      try {
        byte[] b = Optional.ofNullable(decoder.readByteString()).orElseThrow(
            () -> new DecodeException("ByteArrayMessage shall not be null"));

        return new ByteArrayMessage(b);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding ByteArrayMessage", ex);
      }
    }

  }

  /**
   * The request to digest secret key.
   */
  public static class DigestSecretKeyRequest extends ProxyMessage {

    private static final int NUM_FIELDS = 2;

    private final long mechanism;

    private final long objectHandle;

    public DigestSecretKeyRequest(long mechanism, long objectHandle) {
      this.mechanism = mechanism;
      this.objectHandle = objectHandle;
    }

    public long getMechanism() {
      return mechanism;
    }

    public long getObjectHandle() {
      return objectHandle;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeInt(mechanism);
      encoder.writeInt(objectHandle);
    }

    public static DigestSecretKeyRequest decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "DigestSecretKeyRequest");
      try {
        long mechanism = decoder.readLong();
        long objectHandle = decoder.readLong();
        return new DigestSecretKeyRequest(mechanism, objectHandle);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding DigestSecretKeyRequest", ex);
      }
    }

  }

  public enum ProxyErrorCode {

    internalError(1),
    badRequest(2),
    tokenException(3),
    pkcs11Exception(4);

    private final int code;

    ProxyErrorCode(int code) {
      this.code = code;
    }

    public int getCode() {
      return code;
    }

    public static ProxyErrorCode ofCode(int code) {
      for (ProxyErrorCode m : ProxyErrorCode.values()) {
        if (m.code == code) {
          return m;
        }
      }
      return null;
    }

  }

  /**
   * The error response.
   */
  public static class ErrorResponse extends ProxyMessage {

    public static final long CBOR_TAG_ERROR_RESPONSE = 0x80000;

    private static final int NUM_FIELDS = 2;

    private final ProxyErrorCode errorCode;

    private final String detail;

    public ErrorResponse(ProxyErrorCode errorCode, String detail) {
      this.errorCode = errorCode;
      this.detail = detail;
    }

    public ErrorResponse(Throwable t) {
      if (t instanceof PKCS11Exception) {
        this.errorCode = ProxyErrorCode.pkcs11Exception;
        this.detail = Long.toString(((PKCS11Exception) t).getErrorCode());
      } else if (t instanceof TokenException) {
        this.errorCode = ProxyErrorCode.tokenException;
        this.detail = t.getMessage();
      } else {
        this.errorCode = ProxyErrorCode.tokenException;
        this.detail = t.getMessage();
      }
    }

    public ProxyErrorCode getErrorCode() {
      return errorCode;
    }

    public String getDetail() {
      return detail;
    }

    @Override
    public void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeInt(errorCode.code);
      encoder.writeTextString(detail);
    }

    public static ErrorResponse decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "ErrorResponnse");
      try {
        int code = decoder.readInt();
        ProxyErrorCode errorCode = Optional.ofNullable(ProxyErrorCode.ofCode(code)).orElseThrow(
            () -> new DecodeException("unknown error code " + code));
        String detail = decoder.readTextString();
        return new ErrorResponse(errorCode, detail);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding ErrorResponse", ex);
      }
    }

  }

  /**
   * The request to generate-then-save DSA keypair for given keysize.
   */
  public static class GenerateDSAKeyPairByKeysizeRequest extends ProxyMessage {

    private static final int NUM_FIELDS = 3;

    private final int plength;

    private final int qlength;

    private final P11Slot.P11NewKeyControl newKeyControl;

    public GenerateDSAKeyPairByKeysizeRequest(int plength, int qlength, P11Slot.P11NewKeyControl newKeyControl) {
      this.plength = plength;
      this.qlength = qlength;
      this.newKeyControl = newKeyControl;
    }

    public int getPlength() {
      return plength;
    }

    public int getQlength() {
      return qlength;
    }

    public P11Slot.P11NewKeyControl getNewKeyControl() {
      return newKeyControl;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeInt(plength);
      encoder.writeInt(qlength);
      writeNewKeyControl(encoder, newKeyControl);
    }

    public static GenerateDSAKeyPairByKeysizeRequest decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "GenerateDSAKeyPairByKeysizeRequest");
      try {
        int plength = decoder.readInt();
        int qlength = decoder.readInt();
        P11Slot.P11NewKeyControl control = decodeNewKeyControl(decoder);
        return new GenerateDSAKeyPairByKeysizeRequest(plength, qlength, control);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding GenerateDSAKeyPairByKeysizeRequest", ex);
      }
    }

  }

  /**
   * The request to generate-then-destroy DSA keypair for given (P, Q, G).
   */
  public static class GenerateDSAKeyPairOtfRequest extends ProxyMessage {

    private static final int NUM_FIELDS = 3;

    protected final BigInteger p;

    protected final BigInteger q;

    protected final BigInteger g;

    public GenerateDSAKeyPairOtfRequest(BigInteger p, BigInteger q, BigInteger g) {
      this.p = Args.notNull(p, "p");
      this.q = Args.notNull(q, "q");
      this.g = Args.notNull(g, "g");
    }

    public BigInteger getP() {
      return p;
    }

    public BigInteger getQ() {
      return q;
    }

    public BigInteger getG() {
      return g;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeByteString(p.toByteArray());
      encoder.writeByteString(q.toByteArray());
      encoder.writeByteString(g.toByteArray());
    }

    public static GenerateDSAKeyPairOtfRequest decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "GenerateDSAKeyPairOtfRequest");
      try {
        BigInteger p = decoder.readBigInt();
        BigInteger q = decoder.readBigInt();
        BigInteger g = decoder.readBigInt();
        return new GenerateDSAKeyPairOtfRequest(p, q, g);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding GenerateDSAKeyPairOtfRequest", ex);
      }
    }

  }

  /**
   * The request to generate-then-save DSA keypair for given (P, Q, G).
   */
  public static class GenerateDSAKeyPairRequest extends GenerateDSAKeyPairOtfRequest {

    private static final int NUM_FIELDS = 4;

    private final P11Slot.P11NewKeyControl newKeyControl;

    public GenerateDSAKeyPairRequest(BigInteger p, BigInteger q, BigInteger g, P11Slot.P11NewKeyControl newKeyControl) {
      super(p, q, g);
      this.newKeyControl = newKeyControl;
    }

    public P11Slot.P11NewKeyControl getNewKeyControl() {
      return newKeyControl;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeByteString(p.toByteArray());
      encoder.writeByteString(q.toByteArray());
      encoder.writeByteString(g.toByteArray());
      writeNewKeyControl(encoder, newKeyControl);
    }

    public static GenerateDSAKeyPairRequest decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "GenerateDSAKeyPairRequest");
      try {
        BigInteger p = decoder.readBigInt();
        BigInteger q = decoder.readBigInt();
        BigInteger g = decoder.readBigInt();
        P11Slot.P11NewKeyControl control = decodeNewKeyControl(decoder);
        return new GenerateDSAKeyPairRequest(p, q, g, control);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding GenerateDSAKeyPairRequest", ex);
      }
    }

  }

  /**
   * The request to generate-then-destroy EC keypair.
   */
  public static class GenerateECKeyPairOtfRequest extends ProxyMessage {

    private static final int NUM_FIELDS = 1;

    protected final ASN1ObjectIdentifier curveOid;

    public GenerateECKeyPairOtfRequest(ASN1ObjectIdentifier curveOid) {
      this.curveOid = Args.notNull(curveOid, "curveOid");
    }

    public ASN1ObjectIdentifier getCurveOid() {
      return curveOid;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      writeOid(encoder, curveOid);
    }

    public static GenerateECKeyPairOtfRequest decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "GenerateECKeyPairOtfRequest");
      try {
        ASN1ObjectIdentifier curveOid = readOid(decoder);
        return new GenerateECKeyPairOtfRequest(curveOid);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding GenerateECKeyPairOtfRequest", ex);
      }
    }

  }

  /**
   * The request to generate-then-save EC keypair.
   */
  public static class GenerateECKeyPairRequest extends GenerateECKeyPairOtfRequest {

    private static final int NUM_FIELDS = 2;

    private final P11Slot.P11NewKeyControl newKeyControl;

    public GenerateECKeyPairRequest(ASN1ObjectIdentifier curveOid, P11Slot.P11NewKeyControl newKeyControl) {
      super(curveOid);
      this.newKeyControl = newKeyControl;
    }

    public P11Slot.P11NewKeyControl getNewKeyControl() {
      return newKeyControl;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      ProxyMessage.writeOid(encoder, curveOid);
      ProxyMessage.writeNewKeyControl(encoder, newKeyControl);
    }

    public static GenerateECKeyPairRequest decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "GenerateECKeyPairRequest");
      try {
        ASN1ObjectIdentifier curveOid = ProxyMessage.readOid(decoder);
        P11Slot.P11NewKeyControl control = ProxyMessage.decodeNewKeyControl(decoder);
        return new GenerateECKeyPairRequest(curveOid, control);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding GenerateECKeyPairRequest", ex);
      }
    }

  }

  /**
   * The request to generate-then-destroy RSA keypair.
   */
  public static class GenerateRSAKeyPairOtfRequest extends ProxyMessage {

    private static final int NUM_FIELDS = 2;

    protected final int keySize;

    protected final BigInteger publicExponent;

    public GenerateRSAKeyPairOtfRequest(int keySize, BigInteger publicExponent) {
      this.keySize = keySize;
      this.publicExponent = publicExponent;
    }

    public int getKeySize() {
      return keySize;
    }

    public BigInteger getPublicExponent() {
      return publicExponent;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeInt(keySize);
      encoder.writeByteString(publicExponent == null ? null : publicExponent.toByteArray());
    }

    public static GenerateRSAKeyPairOtfRequest decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "GenerateRSAKeyPairOtfRequest");
      try {
        int keysize = decoder.readInt();
        BigInteger publicExponent = decoder.readBigInt();
        return new GenerateRSAKeyPairOtfRequest(keysize, publicExponent);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding GenerateRSAKeyPairOtfRequest", ex);
      }
    }

  }

  /**
   * The request to generate-then-save RSA keypair.
   */
  public static class GenerateRSAKeyPairRequest extends GenerateRSAKeyPairOtfRequest {

    private static final int NUM_FIELDS = 2;

    private final P11Slot.P11NewKeyControl newKeyControl;

    public GenerateRSAKeyPairRequest(int keySize, BigInteger publicExponent, P11Slot.P11NewKeyControl newKeyControl) {
      super(keySize, publicExponent);
      this.newKeyControl = newKeyControl;
    }

    public P11Slot.P11NewKeyControl getNewKeyControl() {
      return newKeyControl;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeInt(keySize);
      writeBigInt(encoder, publicExponent);
      writeNewKeyControl(encoder, newKeyControl);
    }

    public static GenerateRSAKeyPairRequest decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "GenerateRSAKeyPairRequest");
      try {
        int keysize = decoder.readInt();
        BigInteger publicExponent = decoder.readBigInt();
        P11Slot.P11NewKeyControl control = decodeNewKeyControl(decoder);
        return new GenerateRSAKeyPairRequest(keysize, publicExponent, control);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding GenerateRSAKeyPairRequest", ex);
      }
    }

  }

  /**
   * The request to generate-then-destroy SM2 keypair.
   */
  public static class GenerateSecretKeyRequest extends ProxyMessage {

    private static final int NUM_FIELDS = 3;
    private final long keyType;
    private final Integer keySize;
    private final P11Slot.P11NewKeyControl newKeyControl;

    public GenerateSecretKeyRequest(long keyType, Integer keySize, P11Slot.P11NewKeyControl newKeyControl) {
      this.keyType = keyType;
      this.keySize = keySize;
      this.newKeyControl = newKeyControl;
    }

    public long getKeyType() {
      return keyType;
    }

    public Integer getKeySize() {
      return keySize;
    }

    public P11Slot.P11NewKeyControl getNewOKeyControl() {
      return newKeyControl;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeInt(keyType);
      encoder.writeIntObj(keySize);
      writeNewKeyControl(encoder, newKeyControl);
    }

    public static GenerateSecretKeyRequest decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "GenerateSecretKeyRequest");
      try {
        long keyType = decoder.readLong();
        Integer keySize = decoder.readIntObj();
        P11Slot.P11NewKeyControl control = decodeNewKeyControl(decoder);
        return new GenerateSecretKeyRequest(keyType, keySize, control);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding GenerateSecretKeyRequest", ex);
      }
    }

  }

  /**
   * The request to generate-then-save SM2 keypair.
   */
  public static class GenerateSM2KeyPairRequest extends ProxyMessage {

    private static final int NUM_FIELDS = 1;

    private final P11Slot.P11NewKeyControl newKeyControl;

    public GenerateSM2KeyPairRequest(P11Slot.P11NewKeyControl newKeyControl) {
      this.newKeyControl = newKeyControl;
    }

    public P11Slot.P11NewKeyControl getNewKeyControl() {
      return newKeyControl;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      writeNewKeyControl(encoder, newKeyControl);
    }

    public static GenerateSM2KeyPairRequest decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "GenerateSM2KeyPairRequest");
      P11Slot.P11NewKeyControl control = decodeNewKeyControl(decoder);
      return new GenerateSM2KeyPairRequest(control);
    }

  }

  /**
   * The request to get mechanism infos.
   */
  public static class GetMechanismInfosResponse extends ProxyMessage {

    private final Map<Long, MechanismInfo> mechamismInfoMap;

    public GetMechanismInfosResponse(Map<Long, MechanismInfo> mechamismInfoMap) {
      this.mechamismInfoMap = mechamismInfoMap;
    }

    @Override
    public void encode0(CborEncoder encoder) throws IOException, EncodeException {
      encoder.writeMapStart(mechamismInfoMap.size());
      for (Map.Entry<Long, MechanismInfo> entry : mechamismInfoMap.entrySet()) {
        encoder.writeInt(entry.getKey());
        MechanismInfo mi = entry.getValue();
        if (entry.getValue() == null) {
          encoder.writeNull();
        } else {
          encoder.writeArrayStart(3);
          encoder.writeInt(mi.getMinKeySize());
          encoder.writeInt(mi.getMaxKeySize());
          encoder.writeInt(mi.getFlags());
        }
      }
    }

    public Map<Long, MechanismInfo> getMechamismInfoMap() {
      return mechamismInfoMap;
    }

    public static GetMechanismInfosResponse decode(CborDecoder decoder) throws DecodeException {
      try {
        Integer mapLen = decoder.readNullOrMapLength();
        if (mapLen == null) {
          throw new DecodeException("GetMechanismInfosResponse shall not be null");
        }

        Map<Long, MechanismInfo> map = new HashMap<>(mapLen * 5 / 4);
        for (int i = 0; i < mapLen; i++) {
          long code = decoder.readLong();
          boolean isNull = decoder.readNullOrArrayLength(3);
          if (isNull) {
            map.put(code, null);
          } else {
            long minSize = decoder.readLong();
            long maxSize = decoder.readLong();
            long flags = decoder.readLong();
            map.put(code, new MechanismInfo(minSize, maxSize, flags));
          }
        }

        return new GetMechanismInfosResponse(map);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding GetMechanismInfosResponse", ex);
      }
    }

  }

  /**
   * The message wrapper for ia and label.
   */
  public static class IdLabelMessage extends ProxyMessage {

    private static final int NUM_FIELDS = 2;

      private final byte[] id;

      private final String label;

    public IdLabelMessage(byte[] id, String label) {
      this.id = id;
      this.label = label;
    }

    public byte[] getId() {
      return id;
    }

    public String getLabel() {
      return label;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeByteString(id);
      encoder.writeTextString(label);
    }

    public static IdLabelMessage decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "IdLabelMessage");
      try {
        byte[] id = decoder.readByteString();
        String label = decoder.readTextString();
        return new IdLabelMessage(id, label);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding IdLabelMessage", ex);
      }
    }

  }

  /**
   * The request to import secret key.
   */
  public static class ImportSecretKeyRequest extends ProxyMessage {
    private static final int NUM_FIELDS = 3;
    private final long keyType;
    private final byte[] keyValue;
    private final P11Slot.P11NewKeyControl newKeyControl;

    public ImportSecretKeyRequest(long keyType, byte[] keyValue, P11Slot.P11NewKeyControl newKeyControl) {
      this.keyType = keyType;
      this.keyValue = Args.notNull(keyValue, "keyValue");
      this.newKeyControl = newKeyControl;
    }

    public long getKeyType() {
      return keyType;
    }

    public byte[] getKeyValue() {
      return keyValue;
    }

    public P11Slot.P11NewKeyControl getNewKeyControl() {
      return newKeyControl;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeInt(keyType);
      encoder.writeByteString(keyValue);
      writeNewKeyControl(encoder, newKeyControl);
    }

    public static ImportSecretKeyRequest decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "ImportSecretKeyRequest");
      try {
        long keyType = decoder.readLong();
        byte[] keyValue = decoder.readByteString();
        P11Slot.P11NewKeyControl control = decodeNewKeyControl(decoder);
        return new ImportSecretKeyRequest(keyType, keyValue, control);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding ImportSecretKeyRequest", ex);
      }
    }

  }

  /**
   * The message wrapper for int.
   */
  public static class IntMessage extends ProxyMessage {

    private final int value;

    public IntMessage(int value) {
      this.value = value;
    }

    public int getValue() {
      return value;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeInt(value);
    }

    public static IntMessage decode(CborDecoder decoder) throws DecodeException {
      try {
        int b = Optional.ofNullable(decoder.readIntObj()).orElseThrow(
            () -> new DecodeException("IntMessage shall not be null"));
        return new IntMessage(b);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding IntMessage", ex);
      }
    }

  }

  /**
   * The message wrapper for {@link PKCS11KeyId}.
   */
  public static class KeyIdMessage extends ProxyMessage {
    private static final int NUM_FIELDS = 6;
    private final PKCS11KeyId keyId;

    public KeyIdMessage(PKCS11KeyId keyId) {
      this.keyId = keyId;
    }

    public PKCS11KeyId getKeyId() {
      return keyId;
    }

    @Override
    public void encode0(CborEncoder encoder) throws IOException, EncodeException {
      if (keyId == null) {
        encoder.writeNull();
        return;
      }

      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeInt(keyId.getHandle());
      encoder.writeInt(keyId.getKeyType());
      encoder.writeInt(keyId.getObjectCLass());
      encoder.writeByteString(keyId.getId());
      encoder.writeTextString(keyId.getLabel());
      encoder.writeIntObj(keyId.getPublicKeyHandle());
    }

    public static KeyIdMessage decode(CborDecoder decoder) throws DecodeException {
      PKCS11KeyId keyId = Optional.ofNullable(decodeKeyId(decoder)).orElseThrow(
          () -> new DecodeException("KeyIdMessage shall not be null"));
      return new KeyIdMessage(keyId);
    }

  }

  /**
   * The message wrapper for long[].
   */
  public static class LongArrayMessage extends ProxyMessage {

    private final long[] value;

    public LongArrayMessage(long[] value) {
      this.value = value;
    }

    public long[] getValue() {
      return value;
    }

    @Override
    public void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeLongs(value);
    }

    public static LongArrayMessage decode(CborDecoder decoder) throws DecodeException {
      try {
        long[] value = Optional.ofNullable(decoder.readLongs()).orElseThrow(
            () -> new DecodeException("LongMessage shall not be null"));
        return new LongArrayMessage(value);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding LongArrayMessage", ex);
      }
    }

  }

  /**
   * The message wrapper for long.
   */
  public static class LongMessage extends ProxyMessage {

    private final long value;

    public LongMessage(long value) {
      this.value = value;
    }

    public long getValue() {
      return value;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeInt(value);
    }

    public static LongMessage decode(CborDecoder decoder) throws DecodeException {
      try {
        long b = Optional.ofNullable(decoder.readLongObj()).orElseThrow(
            () -> new DecodeException("LongMessage shall not be null"));
        return new LongMessage(b);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding LongMessage", ex);
      }
    }

  }

  /**
   * The response of getting module capability.
   */
  public static class ModuleCapsResponse extends ProxyMessage {

    private static final int NUM_FIELDS = 5;

    private final boolean readOnly;

    private final int maxMessageSize;

    private final P11ModuleConf.P11NewObjectConf newObjectConf;

    private final List<Long> secretKeyTypes;

    private final List<Long> keyPairTypes;

    public ModuleCapsResponse(boolean readOnly, int maxMessageSize, P11ModuleConf.P11NewObjectConf newObjectConf,
                              List<Long> secretKeyTypes, List<Long> keyPairTypes) {
      this.readOnly = readOnly;
      this.maxMessageSize = maxMessageSize;
      this.newObjectConf = newObjectConf;
      this.secretKeyTypes = secretKeyTypes;
      this.keyPairTypes = keyPairTypes;
    }

    public boolean isReadOnly() {
      return readOnly;
    }

    public int getMaxMessageSize() {
      return maxMessageSize;
    }

    public P11ModuleConf.P11NewObjectConf getNewObjectConf() {
      return newObjectConf;
    }

    public List<Long> getSecretKeyTypes() {
      return secretKeyTypes;
    }

    public List<Long> getKeyPairTypes() {
      return keyPairTypes;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeBoolean(readOnly);
      encoder.writeInt(maxMessageSize);
      if (newObjectConf == null) {
        encoder.writeNull();
      } else {
        encoder.writeArrayStart(2);
        encoder.writeBoolean(newObjectConf.isIgnoreLabel());
        encoder.writeInt(newObjectConf.getIdLength());
      }

      encoder.writeLongs(secretKeyTypes);
      encoder.writeLongs(keyPairTypes);
    }

    public static ModuleCapsResponse decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "ModuleCapsResponse");
      try {
        boolean readOnly = decoder.readBoolean();
        int maxMessageSize = decoder.readInt();
        P11ModuleConf.P11NewObjectConf newObjectConf;
        if (decoder.readNullOrArrayLength(2)) {
          newObjectConf = null;
        } else {
          newObjectConf = new P11ModuleConf.P11NewObjectConf();
          newObjectConf.setIgnoreLabel(decoder.readBoolean());
          newObjectConf.setIdLength(decoder.readInt());
        }

        List<Long> secretKeyTypes = decoder.readLongList();
        List<Long> keyPairTypes = decoder.readLongList();

        return new ModuleCapsResponse(readOnly, maxMessageSize, newObjectConf, secretKeyTypes, keyPairTypes);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding ModuleCapsResponse", ex);
      }
    }

  } // class ServerCaps

  /**
   * The response of getting PKCS#11 key.
   */
  public static class P11KeyResponse extends ProxyMessage {

    private static final int NUM_FIELDS = 9;

    private final PKCS11KeyId keyId;

    private boolean sign;

    private ASN1ObjectIdentifier ecParams;

    private Integer ecOrderBitSize;

    private BigInteger rsaModulus;

    private BigInteger rsaPublicExponent;

    private BigInteger dsaP;

    private BigInteger dsaQ;

    private BigInteger dsaG;

    public P11KeyResponse(P11Key key) {
      Args.notNull(key, "key");
      this.keyId = key.getKeyId();
      this.ecParams = key.getEcParams();
      this.ecOrderBitSize = key.getEcOrderBitSize();
      this.dsaP = key.getDsaP();
      this.dsaQ = key.getDsaQ();
      this.dsaG = key.getDsaG();
      this.rsaModulus = key.getRsaModulus();
      this.rsaPublicExponent = key.getRsaPublicExponent();
      this.sign = key.isSign();
    }

    public P11KeyResponse(PKCS11KeyId keyId) {
      this.keyId = Args.notNull(keyId, "keyId");
    }

    public P11Key getP11Key(HsmProxyP11Slot slot) {
      HsmProxyP11Key key = new HsmProxyP11Key(slot, keyId);
      key.setEcParams(ecParams);
      key.setDsaParameters(dsaP, dsaQ, dsaG);
      key.setRsaMParameters(rsaModulus, rsaPublicExponent);
      key.sign(sign);
      return key;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      writeKeyId(encoder, keyId);
      encoder.writeBoolean(sign);
      writeOid(encoder, ecParams);
      encoder.writeIntObj(ecOrderBitSize);
      writeBigInt(encoder, rsaModulus);
      writeBigInt(encoder, rsaPublicExponent);
      writeBigInt(encoder, dsaP);
      writeBigInt(encoder, dsaQ);
      writeBigInt(encoder, dsaG);
    }

    public static P11KeyResponse decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "ModuleCapsResponse");
      try {
        PKCS11KeyId keyId = decodeKeyId(decoder);
        P11KeyResponse ret = new P11KeyResponse(keyId);
        ret.sign = decoder.readBoolean();
        ret.ecParams = readOid(decoder);
        ret.ecOrderBitSize = decoder.readIntObj();
        ret.rsaModulus = decoder.readBigInt();
        ret.rsaPublicExponent = decoder.readBigInt();
        ret.dsaP = decoder.readBigInt();
        ret.dsaQ = decoder.readBigInt();
        ret.dsaG = decoder.readBigInt();

        return ret;
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding P11KeyResponse", ex);
      }
    }

  }

  /**
   * The request to show details of given slot, and optional given object handle.
   */
  public static class ShowDetailsRequest extends ProxyMessage {

    private static final int NUM_FIELDS = 2;

    private final Long objectHandle;

    private final boolean verbose;

    public ShowDetailsRequest(Long objectHandle, boolean verbose) {
      this.objectHandle = objectHandle;
      this.verbose = verbose;
    }

    public Long getObjectHandle() {
      return objectHandle;
    }

    public boolean isVerbose() {
      return verbose;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeIntObj(objectHandle);
      encoder.writeBoolean(verbose);
    }

    public static ShowDetailsRequest decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "ShowDetailsRequest");
      try {
        Long objectHandle = decoder.readLongObj();
        boolean verbose = decoder.readBoolean();
        return new ShowDetailsRequest(objectHandle, verbose);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding P11KeyResponse", ex);
      }
    }

  }

  /**
   * The request to sign message.
   */
  public static class SignRequest extends ProxyMessage {

    private static final int NUM_FIELDS = 5;

    private static final int TAG_P11ByteArrayParams = 80000;

    private static final int TAG_P11RSAPkcsPssParams = 80001;

    private final long keyHandle;

    private final long mechanism;

    private final P11Params p11params;

    private final ExtraParams extraParams;

    private final byte[] content;

    public SignRequest(long keyHandle, long mechanism, P11Params p11params, ExtraParams extraParams, byte[] content) {
      this.keyHandle = keyHandle;
      this.mechanism = mechanism;
      this.p11params = p11params;
      this.extraParams = extraParams;
      this.content = content;
    }

    public long getKeyHandle() {
      return keyHandle;
    }

    public byte[] getContent() {
      return content;
    }

    public long getMechanism() {
      return mechanism;
    }

    public P11Params getP11params() {
      return p11params;
    }

    public ExtraParams getExtraParams() {
      return extraParams;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(NUM_FIELDS);
      encoder.writeInt(keyHandle);
      encoder.writeInt(mechanism);
      writeP11Params(encoder, p11params);
      writeExtraParams(encoder, extraParams);
      encoder.writeByteString(content);
    }

    public static SignRequest decode(CborDecoder decoder) throws DecodeException {
      assertArraySize(decoder, NUM_FIELDS, "SignRequest");
      try {
        long handle = decoder.readLong();
        long mechanism = decoder.readLong();
        P11Params params = decodeP11Params(decoder);
        ExtraParams extraParams = decodeExtraParams(decoder);
        byte[] content = decoder.readByteString();
        return new SignRequest(handle, mechanism, params, extraParams, content);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding SignRequest", ex);
      }
    }

    private static void writeExtraParams(CborEncoder encoder, ExtraParams params) throws IOException {
      if (params == null) {
        encoder.writeNull();
        return;
      }
      encoder.writeArrayStart(1);
      encoder.writeInt(params.ecOrderBitSize());
    }

    private static ExtraParams decodeExtraParams(CborDecoder decoder) throws DecodeException {
      try {
        if (decoder.readNullOrArrayLength(1)) {
          return null;
        }

        return new ExtraParams().ecOrderBitSize(decoder.readInt());
      } catch (IOException ex) {
        throw new DecodeException("IO error", ex);
      }
    }

    protected static void writeP11Params(CborEncoder encoder, P11Params params)
        throws IOException {
      if (params == null) {
        encoder.writeNull();
        return;
      }

      if (params instanceof P11Params.P11ByteArrayParams) {
        P11Params.P11ByteArrayParams tParams = (P11Params.P11ByteArrayParams) params;
        encoder.writeTag(TAG_P11ByteArrayParams);
        encoder.writeArrayStart(1);
        encoder.writeByteString(tParams.getBytes());
      } else if (params instanceof P11Params.P11RSAPkcsPssParams) {
        P11Params.P11RSAPkcsPssParams tParams = (P11Params.P11RSAPkcsPssParams) params;
        encoder.writeTag(TAG_P11RSAPkcsPssParams);
        encoder.writeArrayStart(3);
        encoder.writeInt(tParams.getHashAlgorithm());
        encoder.writeInt(tParams.getMaskGenerationFunction());
        encoder.writeInt(tParams.getSaltLength());
      } else {
        throw new IllegalStateException("unknown params " + params.getClass().getName());
      }
    }

    public static P11Params decodeP11Params(CborDecoder decoder) throws DecodeException {
      try {
        Long tag = decoder.readTagObj();
        if (tag == null) {
          return null;
        }

        if (TAG_P11ByteArrayParams == tag) {
          assertArraySize(decoder, 1, "P11ByteArrayParams");
          return new P11Params.P11ByteArrayParams(decoder.readByteString());
        } else if (TAG_P11RSAPkcsPssParams == tag) {
          assertArraySize(decoder, 3, "P11RSAPkcsPssParams");
          long hashAlgorithm = decoder.readLong();
          long maskGenerationFunction = decoder.readLong();
          int saltLength = decoder.readInt();
          return new P11Params.P11RSAPkcsPssParams(hashAlgorithm, maskGenerationFunction, saltLength);
        } else {
          throw new DecodeException("unknown tag " + tag);
        }
      } catch (IOException ex) {
        throw new DecodeException("IO error", ex);
      }
    }

  }

  /**
   * The response of getting slot identifiers.
   */
  public static class SlotIdsResponse extends ProxyMessage {

    private final List<P11SlotId> slotIds;

    public SlotIdsResponse(List<P11SlotId> slotIds) {
      this.slotIds = Args.notNull(slotIds, "slotIds");
    }

    public List<P11SlotId> getSlotIds() {
      return slotIds;
    }

    @Override
    protected void encode0(CborEncoder encoder) throws EncodeException, IOException {
      encoder.writeArrayStart(slotIds.size());
      for (P11SlotId slotId : slotIds) {
        encoder.writeArrayStart(2);
        encoder.writeInt(slotId.getIndex());
        encoder.writeInt(slotId.getId());
      }
    }

    public static SlotIdsResponse decode(CborDecoder decoder) throws DecodeException {
      try {
        int arrayLen = Optional.ofNullable(decoder.readNullOrArrayLength()).orElseThrow(
            () -> new DecodeException("SlotIdsResponse shall not be null"));

        List<P11SlotId> list = new ArrayList<>(arrayLen);
        for (int i = 0; i < arrayLen; i++) {
          assertArraySize(decoder, 2, "P11SlotId");
          int index = decoder.readInt();
          long id = decoder.readLong();
          list.add(new P11SlotId(index, id));
        }

        return new SlotIdsResponse(list);
      } catch (IOException ex) {
        throw new DecodeException("IO error decoding SlotIdsResponse", ex);
      }
    }
  }
}
