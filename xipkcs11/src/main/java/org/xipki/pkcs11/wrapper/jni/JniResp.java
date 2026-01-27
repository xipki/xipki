// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.jni;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.PKCS11Exception;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Every Parameters-class implements this interface.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class JniResp {

  public static final long CKR_JNI_MEM_ERROR          = 0xFFFFFFFFL;
  public static final long CKR_JNI_OPEN_LIB           = 0xFFFFFFFEL;
  public static final long CKR_JNI_C_GetFunctionList  = 0xFFFFFFFDL;
  public static final long CKR_JNI_NO_MODULE          = 0xFFFFFFFCL;

  public static final long CKR_JNI_BAD_OP             = 0xFFFFFFFAL;
  public static final long CKR_JNI_BAD_RESP           = 0xFFFFFFF9L;
  public static final long CKR_JNI_BAD_TEMPLATE       = 0xFFFFFFF8L;
  public static final long CKR_JNI_BAD_PARAMS         = 0xFFFFFFF7L;
  public static final long CKR_JNI_BAD_ARG            = 0xFFFFFFF6L;

  public static final byte ErrResp    = 1;
  public static final byte SimpleResp = 2;
  public static final byte LongResp   = 3;

  protected final byte type;

  public JniResp(byte type) {
    this.type = type;
  }

  public abstract byte[] getEncoded(Arch arch);

  public static JniResp decodeSucc(Arch arch, byte[] encoded)
      throws PKCS11Exception {
    JniResp resp = decode(arch, encoded);
    if (resp instanceof JniErrResp) {
      throw ((JniErrResp) resp).asException();
    }
    return resp;
  }

  public static JniResp decode(Arch arch, byte[] encoded)
      throws PKCS11Exception {
    if (encoded == null || encoded.length < 1) {
      throw new PKCS11Exception(JniErrResp.CKR_JNI_BAD_RESP);
    }

    byte type = encoded[0];

    AtomicInteger off = new AtomicInteger(1);
    switch (type) {
      case ErrResp:
        return new JniErrResp(JniUtil.readLong(arch, encoded, off));
      case SimpleResp:
        return JniSimpleResp.INSTANCE;
      case LongResp:
        return new JniLongResp(JniUtil.readLong(arch, encoded, off));
      default:
        throw new PKCS11Exception(JniErrResp.CKR_JNI_BAD_RESP);
    }
  }

  /**
   * Error response returned by the JNI peer.
   *
   * @author Lijun Liao (xipki)
   */
  public static class JniErrResp extends JniResp {

    private final long ckr;

    public JniErrResp(long ckr) {
      super(ErrResp);
      this.ckr = ckr;
    }

    public long ckr() {
      return ckr;
    }

    @Override
    public byte[] getEncoded(Arch arch) {
      byte[] dest = new byte[1 + arch.longSize()];
      writeTo(arch, dest);
      return dest;
    }

    public void writeTo(Arch arch, byte[] bytes) {
      bytes[0] = type;
      JniUtil.writeLong(arch, ckr, bytes, new AtomicInteger(1));
    }

    public PKCS11Exception asException() {
      return new PKCS11Exception(ckr);
    }

  }

  /**
   * Response returned by the JNI peer, it contains content of a long.
   *
   * @author Lijun Liao (xipki)
   */
  public static class JniLongResp extends JniResp {

    private final long value;

    public JniLongResp(long value) {
      super(LongResp);
      this.value = value;
    }

    public long value() {
      return value;
    }

    @Override
    public byte[] getEncoded(Arch arch) {
      byte[] dest = new byte[1 + arch.longSize()];
      writeTo(arch, dest);
      return dest;
    }

    public void writeTo(Arch arch, byte[] bytes) {
      bytes[0] = type;
      JniUtil.writeLong(arch, value, bytes, new AtomicInteger(1));
    }

  }

  /**
   * Response returned by the JNI peer, it contains empty content.
   *
   * @author Lijun Liao (xipki)
   */
  public static class JniSimpleResp extends JniResp {

    public static final JniSimpleResp INSTANCE = new JniSimpleResp();

    private JniSimpleResp() {
      super(SimpleResp);
    }

    @Override
    public byte[] getEncoded(Arch arch) {
      return new byte[] {type};
    }

    public void writeTo(byte[] bytes) {
      bytes[0] = type;
    }

  }

}
