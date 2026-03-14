// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.params.ECDH1_DERIVE_PARAMS;
import org.xipki.pkcs11.wrapper.vendor.SpecialBehaviour;
import org.xipki.pkcs11.wrapper.vendor.VendorEnum;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.HsmUtil;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.security.HashAlgo;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.WeierstraussCurveEnum;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.asn1.Asn1Util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_VALUE_LEN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKD_NULL;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_ENCRYPTED_DATA_INVALID;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_ENCRYPTED_DATA_LEN_RANGE;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_FUNCTION_FAILED;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_MECHANISM_INVALID;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_MECHANISM_PARAM_INVALID;

/**
 * XiPKI component.
 *
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

    try {
      this.curve = WeierstraussCurveEnum.ofEcParamsNonNull(ecParams);
    } catch (XiSecurityException e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "error detecting curve of EC key", e);
    }
    this.sk = new BigInteger(1, value);
  }

  private byte[] ecdsaSignHash(XiHsmVendor vendor, byte[] hashValue, SecureRandom random) {
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
      ASN1EncodableVector v = new ASN1EncodableVector(2);
      v.add(new ASN1Integer(1));
      v.add(new DEROctetString(bytes));
      return org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(new DERSequence(v));
    } else {
      return new org.bouncycastle.asn1.sec.ECPrivateKey(
          curve.getOrder().bitLength(), new BigInteger(1, value));
    }
  }

  @Override
  public byte[] getEncoded() throws HsmException {
    AlgorithmIdentifier algId = new AlgorithmIdentifier(
        X9ObjectIdentifiers.id_ecPublicKey, new ASN1ObjectIdentifier(curve.getOid()));
    org.bouncycastle.asn1.sec.ECPrivateKey asn1Key = getASN1ECPrivateKey();
    try {
      return new PrivateKeyInfo(algId, asn1Key).getEncoded();
    } catch (IOException ex) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "error encoding " + getClass().getName(), ex);
    }
  }

  @Override
  public byte[] sign(XiMechanism mechanism, byte[] data, SecureRandom random)
      throws HsmException {
    if (!isSign()) {
      throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED, "CKA_SIGN != TRUE");
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

  @Override
  public byte[] deriveKey(XiMechanism mechanism, XiTemplate template) throws HsmException {
    if (!isDerive()) {
      throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED, "CKA_DERIVE != TRUE");
    }

    long ckm = mechanism.getCkm();
    Object params = mechanism.getParameter();
    if (ckm == PKCS11T.CKM_ECDH1_DERIVE) {
      int valueLen = template.removeNonNullInt(CKA_VALUE_LEN);
      if (!(valueLen >= 1 && valueLen <= curve.getFieldByteSize())) {
        throw new HsmException(CKR_ATTRIBUTE_VALUE_INVALID, "invalid CKA_VALUE_LEN " + valueLen);
      }

      if (!(params instanceof ECDH1_DERIVE_PARAMS)) {
        throw new HsmException(CKR_MECHANISM_PARAM_INVALID,
            "params not allowed: " + params.getClass().getName());
      }

      if (vendor.getVendorEnum() == VendorEnum.CLOUDHSM) {
        throw new HsmException(CKR_FUNCTION_FAILED, "simulate CloudHSM's behavior");
      }

      ECDH1_DERIVE_PARAMS p = (ECDH1_DERIVE_PARAMS) params;
      long kdf = p.kdf();
      if (kdf != CKD_NULL) {
        throw new HsmException(CKR_MECHANISM_PARAM_INVALID,
            "parameter.kdf not allowed: " + PKCS11T.codeToName(Category.CKD, kdf));
      }

      byte[] sharedData = p.sharedData();
      if (!(sharedData == null || sharedData.length == 0)) {
        throw new HsmException(CKR_MECHANISM_PARAM_INVALID, "parameter.sharedData != NULL");
      }

      int size = curve.getFieldByteSize();
      byte[] publicData = p.publicData();

      if (vendor.hasSpecialBehaviour(SpecialBehaviour.ECDH_DER_ECPOINT)) {
        try {
          publicData = Asn1Util.readOctetsFromASN1OctetString(publicData);
        } catch (CodecException e) {
          throw new HsmException(CKR_ENCRYPTED_DATA_INVALID, "publicData is not DER-encoded", e);
        }
      }

      if (publicData.length != 1 + size * 2) {
        throw new HsmException(CKR_MECHANISM_PARAM_INVALID, "invalid parameters.publicData");
      }

      int expLen = 1 + 2 * curve.getFieldByteSize();
      if (publicData.length != expLen) {
        throw new HsmException(CKR_ENCRYPTED_DATA_LEN_RANGE,
            "publicData.length != " + expLen + ": " + publicData.length);
      }

      ECPoint peerPoint ;
      try {
        peerPoint = curve.decodePoint(publicData);
      } catch (XiSecurityException e) {
        throw new HsmException(CKR_MECHANISM_PARAM_INVALID, "invalid publicData", e);
      }
      BigInteger bnX = peerPoint.multiply(sk).normalize().getXCoord().toBigInteger();
      byte[] bytes = BigIntegers.asUnsignedByteArray(size, bnX);
      return valueLen == bytes.length ? bytes
          : Arrays.copyOfRange(bytes, bytes.length - valueLen, bytes.length);
    } else {
      throw new HsmException(CKR_MECHANISM_INVALID, "Mechanism " +
          PKCS11T.ckmCodeToName(ckm) + " is not supported");
    }
  }

  public static XiWeierstrassECPrivateKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    byte[] ecParams = attrs.removeNonNullByteArray(PKCS11T.CKA_EC_PARAMS);
    byte[] value = attrs.removeNonNullByteArray(PKCS11T.CKA_VALUE);
    long keyType = PKCS11T.CKK_EC;
    XiWeierstrassECPrivateKey ret;
    if (WeierstraussCurveEnum.ofEcParams(ecParams) == WeierstraussCurveEnum.SM2) {
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
