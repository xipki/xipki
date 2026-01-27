// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.attr.XiTemplateChecker;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.util.codec.Args;

import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_EC_PARAMS;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_EC_POINT;

/**
 * @author Lijun Liao (xipki)
 */
abstract class XiECPublicKey extends XiPublicKey {

  /**
   * As in {@link XiECPrivateKey#ecParams}.
   */
  protected final byte[] ecParams;

  /**
   * Public EC Point of the EC public key.
   * <ul>
   * <li>For Edwards EC Key:
   * <p>
   * Public key bytes in little endian order as defined in RFC 7748.
   * </li>
   * <li>For Montgomery EC Key
   * <p>
   * Public key bytes in little endian order as defined in RFC 8032
   * </li>
   * <li>For Weierstrass EC Key
   * <p>
   * DER-encoding of ANSI X9.62 ECPoint value Q.
   * </li>
   * </ul>
   */
  protected final byte[] ecPoint;

  protected XiECPublicKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, long keyType,
      Long keyGenMechanism, byte[] ecParams, byte[] ecPoint) {
    super(vendor, cku, newObjectMethod, handle, inToken, keyType,
        keyGenMechanism);
    this.ecParams = Args.notNull(ecParams, "ecParams");
    this.ecPoint  = Args.notNull(ecPoint, "ecPoint");
  }

  @Override
  protected void assertAttributesSettable(XiTemplate attrs)
      throws HsmException {
    XiTemplateChecker.assertEcPublicKeyAttributesSettable(attrs);
  }

  @Override
  protected void doGetAttributes(
      List<XiAttribute> res, long[] types, boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);

    addAttr(res, types, CKA_EC_PARAMS, ecParams);
    addAttr(res, types, CKA_EC_POINT,  ecPoint);
  }

}
