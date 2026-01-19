// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.attr.XiTemplateChecker;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.pkcs11.xihsm.util.XiConstants;
import org.xipki.util.codec.Args;

import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class XiMLKEMPublicKey extends XiPublicKey {

  private final XiConstants.P11MlkemVariant variant;

  private final byte[] value;

  public XiMLKEMPublicKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, Long keyGenMechanism,
      XiConstants.P11MlkemVariant variant, byte[] value) {
    super(vendor, cku, newObjectMethod, handle, inToken,
        PKCS11T.CKK_ML_KEM, keyGenMechanism);
    this.variant = Args.notNull(variant, "variant");
    this.value = Args.notNull(value, "value");
  }

  @Override
  protected void assertAttributesSettable(XiTemplate attrs)
      throws HsmException {
    XiTemplateChecker.assertMlkemPublicKeyAttributesSettable(attrs);
  }

  @Override
  protected void doGetAttributes(List<XiAttribute> res, long[] types,
                                 boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);
    addAttr(res, types, PKCS11T.CKA_PARAMETER_SET, variant.getCode());
    addAttr(res, types, PKCS11T.CKA_VALUE, value);
  }

  public static MLKEMParameters getParams(XiConstants.P11MlkemVariant variant) {
    switch (variant) {
      case MLKEM512:
        return MLKEMParameters.ml_kem_512;
      case MLKEM768:
        return MLKEMParameters.ml_kem_768;
      default:
        return MLKEMParameters.ml_kem_1024;
    }
  }

  public static XiMLKEMPublicKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    long variantCode = attrs.removeNonNullLong(PKCS11T.CKA_PARAMETER_SET);
    XiConstants.P11MlkemVariant variant =
        XiConstants.P11MlkemVariant.ofCode(variantCode);
    byte[] value = attrs.removeNonNullByteArray(PKCS11T.CKA_VALUE);

    XiMLKEMPublicKey ret = new XiMLKEMPublicKey(
        vendor, cku, newObjectMethod,
        handle, inToken, keyGenMechanism, variant, value);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
