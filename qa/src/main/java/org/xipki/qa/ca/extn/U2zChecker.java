// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca.extn;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extensions;
import org.xipki.ca.api.profile.Certprofile.ExtensionControl;
import org.xipki.security.ObjectIdentifiers.Extn;

/**
 * Checker for extensions whose name is from U to Z.
 * @author Lijun Liao (xipki)
 */

class U2zChecker extends ExtensionChecker {

  U2zChecker(ExtensionsChecker parent) {
    super(parent);
  }

  void checkExtnValidityModel(
      StringBuilder failureMsg, byte[] extensionValue, Extensions requestedExtns, ExtensionControl extControl) {
    ASN1ObjectIdentifier conf = caller.getValidityModelId();
    if (conf == null) {
      caller.checkConstantExtnValue(Extn.id_extension_validityModel,
          failureMsg, extensionValue, requestedExtns, extControl);
      return;
    }

    ASN1Sequence seq = ASN1Sequence.getInstance(extensionValue);
    ASN1ObjectIdentifier extValue = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
    if (!conf.equals(extValue)) {
      CheckerUtil.addViolation(failureMsg, "content", extValue, conf);
    }
  } // method checkExtnValidityModel

}
