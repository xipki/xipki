// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.vendor.SpecialBehaviour;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.GMUtil;
import org.xipki.pkcs11.xihsm.crypt.HashAlgo;
import org.xipki.pkcs11.xihsm.crypt.WeierstraussCurveEnum;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.HsmUtil;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.asn1.Asn1Util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class XiSm2ECPrivateKey extends XiWeierstrassECPrivateKey {

  private final byte[] ecPoint;

  private final byte[] za;

  public XiSm2ECPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, Long keyGenMechanism,
      byte[] ecParams, byte[] value, byte[] ecPoint) throws HsmException {
    this(vendor, cku, newObjectMethod, handle, inToken,
        PKCS11T.CKK_VENDOR_SM2, keyGenMechanism, ecParams,
        value, ecPoint);
  }

  public XiSm2ECPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, long keyType,
      Long keyGenMechanism, byte[] ecParams, byte[] value, byte[] ecPoint)
      throws HsmException {
    super(vendor, cku, newObjectMethod, handle, inToken, keyType,
        keyGenMechanism, ecParams, value);
    this.ecPoint = Args.notNull(ecPoint, "ecPoint");
    this.za = GMUtil.getSM2Z(ecPoint);
  }

  @Override
  protected org.bouncycastle.asn1.sec.ECPrivateKey getASN1ECPrivateKey() {
    return new org.bouncycastle.asn1.sec.ECPrivateKey(
        curve.getOrder().bitLength(), new BigInteger(1, value),
        new DERBitString(ecPoint), null);
  }

  @Override
  protected void doGetAttributes(List<XiAttribute> res, long[] types,
                                 boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);

    addAttr(res, types, PKCS11T.CKA_EC_POINT, ecPoint);
  }

  @Override
  public byte[] sign(XiMechanism mechanism, byte[] data,
                            SecureRandom random)
      throws HsmException {
    if (!isSign()) {
      throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED,
          "CKA_SIGN != TRUE");
    }

    long ckm = mechanism.getCkm();
    if (ckm == PKCS11T.CKM_VENDOR_SM2) {
      HsmUtil.assertNullParameter(mechanism);
      return signEhash(mechanism.getVendor(), data, random);
    } else if (ckm == PKCS11T.CKM_VENDOR_SM2_SM3) {
      // no IDA is supported yet
      HsmUtil.assertNullParameter(mechanism);
      byte[] ehash = HashAlgo.SM3.hash(za, data);
      return signEhash(mechanism.getVendor(), ehash, random);
    } else {
      return super.sign(mechanism, data, random);
    }
  }

  private byte[] signEhash(XiHsmVendor vendor, byte[] hash,
                           SecureRandom random) {
    WeierstraussCurveEnum SM2 = WeierstraussCurveEnum.SM2;
    BigInteger order = SM2.getOrder();
    BigInteger eh= new BigInteger(1, hash);

    BigInteger r;
    BigInteger s;

    while (true) {
      BigInteger k = new BigInteger(order.bitLength(), random);
      k = k.mod(order);

      // (x, y) = k * G
      ECPoint kG = SM2.multiplyBase(k);
      BigInteger x = kG.getXCoord().toBigInteger();

      // r = e + x
      r = eh.add(x).mod(order);
      if (r.signum() == 0) {
        continue;
      }

      // s = (1 + d)^-1 * (k -r * d)
      BigInteger inv = sk.add(BigInteger.ONE).modInverse(order);
      BigInteger rd  = r.multiply(sk).mod(order);
      BigInteger k_minus_rd = k.subtract(rd).mod(order);
      if (k_minus_rd.signum() == -1) {
        k_minus_rd = order.add(k_minus_rd);
      }

      s = inv.multiply(k_minus_rd).mod(order);
      if (s.signum() != 0) {
        break;
      }
    }

    byte[] sig = new byte[64];
    BigIntegers.asUnsignedByteArray(r, sig, 0, 32);
    BigIntegers.asUnsignedByteArray(s, sig, 32, 32);
    if (vendor.hasSpecialBehaviour(SpecialBehaviour.SM2_X962_SIGNATURE)) {
      sig = Asn1Util.dsaSigPlainToX962(sig);
    }
    return sig;
  }

  public static XiSm2ECPrivateKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    byte[] ecParams = attrs.removeNonNullByteArray(
        PKCS11T.CKA_EC_PARAMS);
    byte[] value = attrs.removeNonNullByteArray(PKCS11T.CKA_VALUE);

    byte[] bytes = attrs.removeByteArray(PKCS11T.CKA_EC_POINT);
    byte[] ecPoint = null;
    if (bytes != null) {
      ecPoint = HsmUtil.getOctetStringValue("EC_Point", bytes);
    }

    XiSm2ECPrivateKey ret = new XiSm2ECPrivateKey(
        vendor, cku, newObjectMethod,
        handle, inToken, keyGenMechanism, ecParams, value, ecPoint);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
