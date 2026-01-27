// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.params.CkParams;
import org.xipki.pkcs11.wrapper.params.NullParams;
import org.xipki.pkcs11.wrapper.params.SIGN_ADDITIONAL_CONTEXT;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.attr.XiTemplateChecker;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.pkcs11.xihsm.util.XiConstants;
import org.xipki.util.codec.Args;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class XiMLDSAPrivateKey extends XiPrivateKey {

  private final XiConstants.P11MldsaVariant variant;

  private final byte[] sk;

  private final java.security.PrivateKey jceKey;

  public XiMLDSAPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, Long keyGenMechanism,
      XiConstants.P11MldsaVariant variant, byte[] sk) throws HsmException {
    super(vendor, cku, newObjectMethod, handle, inToken,
        PKCS11T.CKK_ML_DSA, keyGenMechanism);
    this.variant = Args.notNull(variant, "variant");
    this.sk = sk;

    try {
      this.jceKey = BouncyCastleProvider.getPrivateKey(new PrivateKeyInfo(
          new AlgorithmIdentifier(this.variant.getOid()), sk));
    } catch (Exception e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "error constructing JCE ML-DSA private key");
    }
  }

  @Override
  public byte[] getEncoded() throws HsmException {
    try {
      return new PrivateKeyInfo(
          new AlgorithmIdentifier(this.variant.getOid()), sk).getEncoded();
    } catch (IOException ex) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "error encoding " + getClass().getName(), ex);
    }
  }

  @Override
  protected void assertAttributesSettable(XiTemplate attrs)
      throws HsmException {
    XiTemplateChecker.assertMldsaPrivateKeyAttributesSettable(attrs);
  }

  @Override
  protected void doGetAttributes(List<XiAttribute> res, long[] types,
                                 boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);
    addAttr(res, types, PKCS11T.CKA_PARAMETER_SET,
        variant.getCode());

    if (withAll || !isSensitive()) {
      addAttr(res, types, PKCS11T.CKA_VALUE, sk);
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

    long ckm = mechanism.getCkm();
    if (ckm != PKCS11T.CKM_ML_DSA) {
      throw new HsmException(PKCS11T.CKR_MECHANISM_INVALID,
          "Invalid mechanism " + PKCS11T.ckmCodeToName(ckm));
    }

    byte[] context = null;
    CkParams params = mechanism.getParameter();
    if (params != null && !params.equals(NullParams.INSTANCE)) {
      if (!(params instanceof SIGN_ADDITIONAL_CONTEXT)) {
        throw new HsmException(PKCS11T.CKR_MECHANISM_PARAM_INVALID,
            "Mechanism.parameters is not a CK_SIGN_ADDITIONAL_CONTEXT");
      }

      SIGN_ADDITIONAL_CONTEXT sac = (SIGN_ADDITIONAL_CONTEXT) params;
      context = sac.context();
    }

    try {
      Signature sig = Signature.getInstance("ML-DSA", "BC");
      sig.initSign(jceKey);
      if (context != null) {
        sig.setParameter(new ContextParameterSpec(context));
      }
      sig.update(data);
      try {
        return sig.sign();
      } catch (Exception e) {
        throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
            "error sign()", e);
      }
    } catch (Exception e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "error initializing Signature instance");
    }
  }

  public static XiMLDSAPrivateKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    long variantCode = attrs.removeNonNullLong(
        PKCS11T.CKA_PARAMETER_SET);
    XiConstants.P11MldsaVariant variant =
        XiConstants.P11MldsaVariant.ofCode(variantCode);
    byte[] value = attrs.removeNonNullByteArray(PKCS11T.CKA_VALUE);
    XiMLDSAPrivateKey ret = new XiMLDSAPrivateKey(
        vendor, cku, newObjectMethod,
        handle, inToken, keyGenMechanism, variant, value);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
