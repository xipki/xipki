/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.qa.ca.extn;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extensions;
import org.xipki.ca.api.profile.Certprofile.ExtensionControl;
import org.xipki.security.ObjectIdentifiers.Extn;

import static org.xipki.qa.ca.extn.CheckerUtil.addViolation;

/**
 * Checker for extensions whose name is from U to Z.
 * @author Lijun Liao
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
      addViolation(failureMsg, "content", extValue, conf);
    }
  } // method checkExtnValidityModel

}
