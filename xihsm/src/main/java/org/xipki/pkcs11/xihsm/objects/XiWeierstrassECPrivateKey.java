// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.vendor.SpecialBehaviour;
import org.xipki.pkcs11.wrapper.vendor.VendorEnum;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.HashAlgo;
import org.xipki.pkcs11.xihsm.crypt.WeierstraussCurveEnum;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.HsmUtil;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.util.codec.asn1.Asn1Util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @author Lijun Liao (xipki)
 */
public class XiWeierstrassECPrivateKey extends XiECPrivateKey {

  protected final WeierstraussCurveEnum curve;

  protected final BigInteger sk;

  public XiWeierstrassECPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, long keyType,
      Long keyGenMechanism, byte[] ecParams, byte[] value)
      throws HsmException {
    super(vendor, cku, newObjectMethod, handle, inToken, keyType,
        keyGenMechanism, ecParams, value);

    this.curve = WeierstraussCurveEnum.ofEcParamsNonNull(ecParams);
    this.sk = new BigInteger(1, value);
  }

  private byte[] ecdsaSignHash(XiHsmVendor vendor,
                               byte[] hashValue, SecureRandom random) {
    int fieldByteSize = curve.getFieldByteSize();

    if (fieldByteSize < hashValue.length) {
      // take the leftmost bytes
      hashValue = Arrays.copyOf(hashValue, fieldByteSize);
    }
    BigInteger z = new BigInteger(1, hashValue);
    BigInteger order = curve.getOrder();

    BigInteger r;
    BigInteger s;

    while (true) {
      BigInteger k = new BigInteger(order.bitLength(), random).mod(order);

      // (x,y) = k*G
      ECPoint xy = curve.multiplyBase(k);

      r = xy.getXCoord().toBigInteger();
      if (r.signum() == 0) {
        continue;
      }

      // s = k^-1 * (z + rd) mod n
      BigInteger z_rd = r.multiply(sk).add(z).mod(order);
      s = k.modInverse(order).multiply(z_rd).mod(order);
      if (s.signum() != 0) {
        break;
      }
    }

    byte[] sig = new byte[2 * fieldByteSize];
    BigIntegers.asUnsignedByteArray(r, sig, 0, fieldByteSize);
    BigIntegers.asUnsignedByteArray(s, sig, fieldByteSize, fieldByteSize);
    if (vendor.hasSpecialBehaviour(SpecialBehaviour.ECDSA_X962_SIGNATURE)) {
      sig = Asn1Util.dsaSigPlainToX962(sig);
    }
    return sig;
  }

  protected org.bouncycastle.asn1.sec.ECPrivateKey getASN1ECPrivateKey() {
    if (vendor.getVendorEnum() == VendorEnum.UTIMACO) {
      byte[] bytes = BigIntegers.asUnsignedByteArray(sk);
      ASN1Sequence seq = new DERSequence(
          new ASN1Integer(1), new DEROctetString(bytes));
      return org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(seq);
    } else {
      return new org.bouncycastle.asn1.sec.ECPrivateKey(
          curve.getOrder().bitLength(), new BigInteger(1, value));
    }
  }

  @Override
  public byte[] getEncoded() throws HsmException {
    AlgorithmIdentifier algId = new AlgorithmIdentifier(
        X9ObjectIdentifiers.id_ecPublicKey,
        new ASN1ObjectIdentifier(curve.getOid()));
    org.bouncycastle.asn1.sec.ECPrivateKey asn1Key = getASN1ECPrivateKey();
    try {
      return new PrivateKeyInfo(algId, asn1Key).getEncoded();
    } catch (IOException ex) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "error encoding " + getClass().getName(), ex);
    }
  }

  @Override
  public byte[] sign(XiMechanism mechanism, byte[] data,
                            SecureRandom random)
      throws HsmException {
    if (!isSign()) {
      throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED,
          "CKA_SIGN != TRUE");
    }

    HsmUtil.assertNullParameter(mechanism);

    long ckm = mechanism.getCkm();
    if (ckm == PKCS11T.CKM_ECDSA) {
      return ecdsaSignHash(mechanism.getVendor(), data, random);
    }

    HashAlgo hashAlgo =
          (ckm == PKCS11T.CKM_ECDSA_SHA1) ? HashAlgo.SHA1
        : (ckm == PKCS11T.CKM_ECDSA_SHA224) ? HashAlgo.SHA224
        : (ckm == PKCS11T.CKM_ECDSA_SHA256) ? HashAlgo.SHA256
        : (ckm == PKCS11T.CKM_ECDSA_SHA384) ? HashAlgo.SHA384
        : (ckm == PKCS11T.CKM_ECDSA_SHA512) ? HashAlgo.SHA512
        : null;

    if (hashAlgo == null) {
      throw new HsmException(PKCS11T.CKR_MECHANISM_INVALID,
          "unsupported mechanism " + PKCS11T.ckmCodeToName(ckm));
    }

    return ecdsaSignHash(mechanism.getVendor(), hashAlgo.hash(data), random);
  }

  public static XiWeierstrassECPrivateKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    byte[] ecParams = attrs.removeNonNullByteArray(
        PKCS11T.CKA_EC_PARAMS);
    byte[] value = attrs.removeNonNullByteArray(PKCS11T.CKA_VALUE);
    long keyType = PKCS11T.CKK_EC;
    XiWeierstrassECPrivateKey ret;
    if (WeierstraussCurveEnum.ofEcParams(ecParams) ==
        WeierstraussCurveEnum.SM2) {
      byte[] ecPoint = attrs.removeByteArray(PKCS11T.CKA_EC_POINT);
      ret = new XiSm2ECPrivateKey(vendor, cku, newObjectMethod,
          handle, inToken, keyType, keyGenMechanism, ecParams, value, ecPoint);
    } else {
      ret = new XiWeierstrassECPrivateKey(vendor, cku, newObjectMethod,
          handle, inToken, keyType, keyGenMechanism, ecParams, value);
    }

    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
