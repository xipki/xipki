// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.xipki.pkcs11.wrapper.PKCS11T;
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
import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class XiMLKEMPrivateKey extends XiPrivateKey {

  private final XiConstants.P11MlkemVariant variant;

  private final byte[] sk;

  public XiMLKEMPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, Long keyGenMechanism,
      XiConstants.P11MlkemVariant variant, byte[] sk) {
    super(vendor, cku, newObjectMethod, handle, inToken,
        PKCS11T.CKK_ML_KEM, keyGenMechanism);
    this.variant = Args.notNull(variant, "variant");
    this.sk = sk;
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
    XiTemplateChecker.assertMlkemPrivateKeyAttributesSettable(attrs);
  }

  @Override
  protected void doGetAttributes(List<XiAttribute> res, long[] types,
                                 boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);
    addAttr(res, types, PKCS11T.CKA_PARAMETER_SET, variant.getCode());

    if (withAll || !isSensitive()) {
      addAttr(res, types, PKCS11T.CKA_VALUE, sk);
    }
  }

  @Override
  public byte[] decapsulateKey(XiMechanism mechanism, byte[] encapsulatedKey)
      throws HsmException {
    MLKEMPrivateKeyParameters priParams = new MLKEMPrivateKeyParameters(
        XiMLKEMPublicKey.getParams(variant), sk);
    MLKEMExtractor gen = new MLKEMExtractor(priParams);
    return gen.extractSecret(encapsulatedKey);
  }

  public static XiMLKEMPrivateKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    long variantCode = attrs.removeNonNullLong(PKCS11T.CKA_PARAMETER_SET);
    XiConstants.P11MlkemVariant variant =
        XiConstants.P11MlkemVariant.ofCode(variantCode);
    byte[] value = attrs.removeNonNullByteArray(PKCS11T.CKA_VALUE);

    XiMLKEMPrivateKey ret = new XiMLKEMPrivateKey(
        vendor, cku, newObjectMethod,
        handle, inToken, keyGenMechanism, variant, value);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
