// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.attr.XiTemplateChecker;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.util.codec.Args;

import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
abstract class XiECPrivateKey extends XiPrivateKey {

  /**
   * DER-encoding of an ANSI X9.62 Parameters value.
   * <p>
   * The CKA_EC_PARAMS attribute value is known as the "EC domain parameters"
   * and is defined in ANSI X9.62 as a choice of three parameter representation
   * methods with the following syntax:
   * <pre>
   * Parameters ::= CHOICE {
   *   ecParameters   ECParameters,
   *   oId           CURVES.&id({CurveNames}),
   *   implicitlyCA   NULL,
   *   curveName     PrintableString
   * }
   * </pre>
   * <ul>
   * <li> For Edwards EC Key:
   * <p>
   * Edwards EC private keys only support the use of the curveName selection to
   * specify a curve name as defined in [RFC 8032] and the use of the oID
   * selection to specify a curve through an EdDSA algorithm as defined in
   * [RFC 8410]. Note that keys defined by RFC 8032 and RFC 8410 are
   * incompatible.
   * <p>
   *
   * Note that when generating an Edwards EC private key, the EC domain
   * parameters are not specified in the key’s template.  This is because
   * Edwards EC private keys are only generated as part of an Edwards EC key
   * pair, and the EC domain parameters for the pair are specified in the
   * template for the Edwards EC public key.
   * </li>
   * <li>For Montgomery EC Key
   * <p>
   * Montgomery EC public keys only support the use of the curveName selection
   * to specify a curve name as defined in [RFC7748] and the use of the oID
   * selection to specify a curve through an ECDH algorithm as defined in
   * [RFC 8410]. Note that keys defined by RFC 7748 and RFC 8410 are
   * incompatible.
   * </li>
   * <li>For Weierstrass EC Key
   * <p>
   * This allows detailed specification of all required values using choice
   * ecParameters, the use of oId as an object identifier substitute for a
   * particular set of Elliptic Curve domain parameters, or implicitlyCA to
   * indicate that the domain parameters are explicitly defined elsewhere, or
   * curveName to specify a curve name as e.g. define in [ANSI X9.62],
   * [BRAINPOOL], [SEC 2], [LEGIFRANCE].
   * <p>
   * The use of oId or curveName is recommended over the choice ecParameters.
   * The choice implicitlyCA must not be used in Cryptoki.
   * </li>
   * </ul>
   */
  protected final byte[] ecParams;

  /**
   * Secret value of the EC private key.
   * <ul>
   * <li> For Edwards EC Key:
   * <p>
   * Private key bytes in little endian order as defined in RFC 8032.
   * </li>
   * <li>For Montgomery EC Key
   * <p>
   * Private key bytes in little endian order as defined in RFC 8032.
   * </li>
   * <li>For Weierstrass EC Key
   * <p>
   * ANSI X9.62 private value d
   * </li>
   * </ul>
   */
  protected final byte[] value;

  XiECPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, long keyType,
      Long keyGenMechanism, byte[] ecParams, byte[] value) {
    super(vendor, cku, newObjectMethod, handle, inToken, keyType,
        keyGenMechanism);
    this.ecParams = Args.notNull(ecParams, "ecParams");
    this.value    = Args.notNull(value, "value");
  }

  @Override
  protected void assertAttributesSettable(XiTemplate attrs)
      throws HsmException {
    XiTemplateChecker.assertEcPrivateKeyAttributesSettable(attrs);
  }

  @Override
  protected void doGetAttributes(List<XiAttribute> res, long[] types,
                                 boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);

    addAttr(res, types, PKCS11T.CKA_EC_PARAMS, ecParams);

    if (withAll || !isSensitive()) {
      addAttr(res, types, PKCS11T.CKA_VALUE, value);
    }
  }

}
