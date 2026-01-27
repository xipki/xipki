// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.jni.JniResp;
import org.xipki.pkcs11.wrapper.jni.JniUtil;
import org.xipki.pkcs11.wrapper.type.CkType;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Every Parameters-class implements this interface.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class CkParams extends CkType {

  private static final Logger log = LoggerFactory.getLogger(CkParams.class);

  public abstract ParamsType type();

  protected abstract void addContent(
      EncodeList contents);

  private EncodeList getEncodeList() {
    EncodeList contents = new EncodeList().v(type().getCode());
    addContent(contents);
    return contents;
  }

  @Override
  public int hashCode() {
    return getEncodeList().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof CkParams)) {
      return false;
    }

    String aName = getClass().getName();
    String bName = obj.getClass().getName();
    if (!aName.equals(bName)) {
      return false;
    }

    EncodeList a = getEncodeList();
    EncodeList b = ((CkParams) obj).getEncodeList();
    return a.equals(b);
  }

  public int getEncodedLen(Arch arch) {
    return getEncodeList().getEncodedLen(arch);
  }

  public void encodeTo(Arch arch, byte[] dest, AtomicInteger off) {
    getEncodeList().writeTo(arch, dest, off);
  }

  public byte[] getEncoded(Arch arch) {
    EncodeList cte = getEncodeList();
    int len = cte.getEncodedLen(arch);
    byte[] ret = new byte[len];
    AtomicInteger off = new AtomicInteger();
    cte.writeTo(arch, ret, off);
    return ret;
  }

  protected String getCkName() {
    return "CK_" + getClass().getSimpleName();
  }

  public CkParams vendorCopy(PKCS11Module module) {
    return this;
  }

  public String toString(
      String indent, PKCS11Module module, Object... fieldNameValues) {
    return toString(indent, getCkName(), module, fieldNameValues);
  }

  protected static byte[] readByteArray(
      Arch arch, byte[] src, AtomicInteger off) {
    return JniUtil.readByteArray(arch, src, off);
  }

  protected static int readInt(
      Arch arch, byte[] src, AtomicInteger off) {
    return JniUtil.readInt(arch, src, off);
  }

  protected static long readLong(
      Arch arch, byte[] src, AtomicInteger off) {
    return JniUtil.readLong(arch, src, off);
  }

  protected static boolean readBool(byte[] src, AtomicInteger off) {
    return src[off.getAndIncrement()] != 0;
  }

  protected static byte readByte(byte[] src, AtomicInteger off) {
    return src[off.getAndIncrement()];
  }

  protected static void assertType(
      byte[] encoded, AtomicInteger off, ParamsType type)
      throws PKCS11Exception {
    byte byte0 = encoded[off.getAndIncrement()];
    if (byte0 != type.getCode()) {
      ParamsType thisType = ParamsType.ofCode(byte0);
      log.warn("invalid ParamType {}, expected {}",
          thisType == null ? "" + (0xFF & byte0) : thisType, type);
      throw new PKCS11Exception(JniResp.CKR_JNI_BAD_ARG);
    }
  }

  public static CkParams decodeParams(Arch arch, byte[] encoded)
      throws PKCS11Exception {
    return decodeParams(arch, encoded, new AtomicInteger());
  }

  public static CkParams decodeParams(
      Arch arch, byte[] encoded, AtomicInteger off)
      throws PKCS11Exception {
    if (encoded == null || encoded.length < off.get() + 1) {
      throw new PKCS11Exception(JniResp.CKR_JNI_BAD_ARG);
    }

    ParamsType type = ParamsType.ofCode(encoded[off.get()]);
    if (type == null) {
      throw new PKCS11Exception(JniResp.CKR_JNI_BAD_ARG);
    }

    switch (type) {
      case NullParams:
        return NullParams.decode(encoded, off);
      case ByteArrayParams:
        return ByteArrayParams.decode(arch, encoded, off);
      case EDDSA_PARAMS:
        return EDDSA_PARAMS.decode(arch, encoded, off);
      case GCM_PARAMS:
        return GCM_PARAMS.decode(arch, encoded, off);
      case HASH_SIGN_ADDITIONAL_CONTEXT:
        return HASH_SIGN_ADDITIONAL_CONTEXT.decode(arch, encoded, off);
      case LongParams:
        return LongParams.decode(arch, encoded, off);
      case RSA_PKCS_PSS_PARAMS:
        return RSA_PKCS_PSS_PARAMS.decode(arch, encoded, off);
      case SIGN_ADDITIONAL_CONTEXT:
        return SIGN_ADDITIONAL_CONTEXT.decode(arch, encoded, off);
      case XEDDSA_PARAMS:
        return XEDDSA_PARAMS.decode(arch, encoded, off);
      default:
        throw new IllegalStateException("shall not reach here");
    }
  }

}
