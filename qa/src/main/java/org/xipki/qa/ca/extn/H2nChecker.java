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

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.xipki.ca.api.profile.Certprofile.ExtensionControl;
import org.xipki.ca.api.profile.Certprofile.KeyUsageControl;
import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType;
import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType.Base;
import org.xipki.ca.certprofile.xijson.conf.InhibitAnyPolicy;
import org.xipki.ca.certprofile.xijson.conf.NameConstraints;
import org.xipki.qa.ca.IssuerInfo;
import org.xipki.security.KeyUsage;
import org.xipki.security.util.X509Util;
import org.xipki.util.CompareUtil;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.xipki.qa.ca.extn.CheckerUtil.*;
import static org.xipki.util.CollectionUtil.isEmpty;
import static org.xipki.util.CollectionUtil.isNotEmpty;

/**
 * Checker for extensions whose name is from H to N.
 * @author Lijun Liao
 */

class H2nChecker extends ExtensionChecker {

  private static final List<String> ALL_USAGES = Arrays.asList(
      KeyUsage.digitalSignature.getName(), // 0
      KeyUsage.contentCommitment.getName(), // 1
      KeyUsage.keyEncipherment.getName(), // 2
      KeyUsage.dataEncipherment.getName(), // 3
      KeyUsage.keyAgreement.getName(), // 4
      KeyUsage.keyCertSign.getName(), // 5
      KeyUsage.cRLSign.getName(), // 6
      KeyUsage.encipherOnly.getName(), // 7
      KeyUsage.decipherOnly.getName()); // 8

  H2nChecker(ExtensionsChecker parent) {
    super(parent);
  }

  void checkExtnInhibitAnyPolicy(
      StringBuilder failureMsg, byte[] extensionValue, Extensions requestedExtns, ExtensionControl extControl) {
    InhibitAnyPolicy conf = caller.getInhibitAnyPolicy();
    if (conf == null) {
      caller.checkConstantExtnValue(Extension.inhibitAnyPolicy, failureMsg, extensionValue, requestedExtns, extControl);
      return;
    }

    ASN1Integer asn1Int = ASN1Integer.getInstance(extensionValue);
    int isSkipCerts = asn1Int.getPositiveValue().intValue();
    if (isSkipCerts != conf.getSkipCerts()) {
      addViolation(failureMsg, "skipCerts", isSkipCerts, conf.getSkipCerts());
    }
  } // method checkExtnInhibitAnyPolicy

  void checkExtnIssuerAltNames(StringBuilder failureMsg, byte[] extensionValue, IssuerInfo issuerInfo) {
    byte[] caSubjectAltExtensionValue = issuerInfo.getCert().getExtensionCoreValue(
        Extension.subjectAlternativeName);
    if (caSubjectAltExtensionValue == null) {
      failureMsg.append("issuerAlternativeName is present but expected 'none'; ");
      return;
    }

    if (!Arrays.equals(caSubjectAltExtensionValue, extensionValue)) {
      addViolation(failureMsg, "issuerAltNames", hex(extensionValue), hex(caSubjectAltExtensionValue));
    }
  } // method checkExtnIssuerAltNames

  void checkExtnKeyUsage(
      StringBuilder failureMsg, boolean[] usages, Extensions requestedExtns, ExtensionControl extnControl) {
    int len = usages.length;

    if (len > 9) {
      failureMsg.append("invalid syntax: size of valid bits is larger than 9: ").append(len);
      failureMsg.append("; ");
    }

    Set<String> isUsages = new HashSet<>();
    for (int i = 0; i < len; i++) {
      if (usages[i]) {
        isUsages.add(ALL_USAGES.get(i));
      }
    }

    Set<String> expectedUsages = new HashSet<>();
    Set<KeyUsageControl> requiredKeyusage = getKeyusage(true);
    for (KeyUsageControl usage : requiredKeyusage) {
      expectedUsages.add(usage.getKeyUsage().getName());
    }

    Set<KeyUsageControl> optionalKeyusage = getKeyusage(false);
    if (requestedExtns != null && extnControl.isRequest()
        && isNotEmpty(optionalKeyusage)) {
      Extension extension = requestedExtns.getExtension(Extension.keyUsage);
      if (extension != null) {
        org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage =
            org.bouncycastle.asn1.x509.KeyUsage.getInstance(extension.getParsedValue());
        for (KeyUsageControl k : optionalKeyusage) {
          if (reqKeyUsage.hasUsages(k.getKeyUsage().getBcUsage())) {
            expectedUsages.add(k.getKeyUsage().getName());
          }
        }
      }
    }

    if (isEmpty(expectedUsages)) {
      byte[] constantExtValue = caller.getConstantExtensionValue(Extension.keyUsage);
      if (constantExtValue != null) {
        expectedUsages = getKeyUsage(constantExtValue);
      }
    }

    Set<String> diffs = CheckerUtil.strInBnotInA(expectedUsages, isUsages);
    if (isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs).append(" are present but not expected; ");
    }

    diffs = CheckerUtil.strInBnotInA(isUsages, expectedUsages);
    if (isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs).append(" are absent but are required; ");
    }
  } // method checkExtnKeyUsage

  Set<KeyUsageControl> getKeyusage(boolean required) {
    Set<KeyUsageControl> ret = new HashSet<>();

    Set<KeyUsageControl> controls = getCertprofile().extensions().getKeyusages();
    if (controls != null) {
      for (KeyUsageControl control : controls) {
        if (control.isRequired() == required) {
          ret.add(control);
        }
      }
    }
    return ret;
  } // method getKeyusage

  void checkExtnNameConstraints(
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns, ExtensionControl extnControl) {
    NameConstraints nameConstraints = caller.getNameConstraints();

    if (nameConstraints == null) {
      caller.checkConstantExtnValue(Extension.nameConstraints, failureMsg, extnValue, requestedExtns, extnControl);
      return;
    }

    org.bouncycastle.asn1.x509.NameConstraints tmpNameConstraints =
        org.bouncycastle.asn1.x509.NameConstraints.getInstance(extnValue);

    checkExtnNameConstraintsSubtrees(failureMsg, "PermittedSubtrees",
        tmpNameConstraints.getPermittedSubtrees(),  nameConstraints.getPermittedSubtrees());
    checkExtnNameConstraintsSubtrees(failureMsg, "ExcludedSubtrees",
        tmpNameConstraints.getExcludedSubtrees(), nameConstraints.getExcludedSubtrees());
  } // method checkExtnNameConstraints

  private void checkExtnNameConstraintsSubtrees(
      StringBuilder failureMsg, String description, GeneralSubtree[] subtrees,
      List<GeneralSubtreeType> expectedSubtrees) {
    int isSize = (subtrees == null) ? 0 : subtrees.length;
    int expSize = (expectedSubtrees == null) ? 0 : expectedSubtrees.size();
    if (isSize != expSize) {
      addViolation(failureMsg, "size of " + description, isSize, expSize);
      return;
    }

    if (subtrees == null || expectedSubtrees == null) {
      return;
    }

    for (int i = 0; i < isSize; i++) {
      GeneralSubtree isSubtree = subtrees[i];
      GeneralSubtreeType expSubtree = expectedSubtrees.get(i);
      BigInteger bigInt = isSubtree.getMinimum();
      int isMinimum = (bigInt == null) ? 0 : bigInt.intValue();
      Integer minimum = expSubtree.getMinimum();
      int expMinimum = (minimum == null) ? 0 : minimum;
      String desc = description + " [" + i + "]";
      if (isMinimum != expMinimum) {
        addViolation(failureMsg, "minimum of " + desc, isMinimum, expMinimum);
      }

      bigInt = isSubtree.getMaximum();
      Integer isMaximum = (bigInt == null) ? null : bigInt.intValue();
      Integer expMaximum = expSubtree.getMaximum();
      if (!CompareUtil.equalsObject(isMaximum, expMaximum)) {
        addViolation(failureMsg, "maxmum of " + desc, isMaximum, expMaximum);
      }

      GeneralName isBase = isSubtree.getBase();

      Base expBase0 = expSubtree.getBase();

      GeneralName expBase;
      if (expSubtree.getBase().getDirectoryName() != null) {
        expBase = new GeneralName(X509Util.reverse(new X500Name(expBase0.getDirectoryName())));
      } else if (expBase0.getDnsName() != null) {
        expBase = new GeneralName(GeneralName.dNSName, expBase0.getDnsName());
      } else if (expBase0.getIpAddress() != null) {
        expBase = new GeneralName(GeneralName.iPAddress, expBase0.getIpAddress());
      } else if (expBase0.getRfc822Name() != null) {
        expBase = new GeneralName(GeneralName.rfc822Name, expBase0.getRfc822Name());
      } else if (expBase0.getUri() != null) {
        expBase = new GeneralName(GeneralName.uniformResourceIdentifier, expBase0.getUri());
      } else {
        throw new IllegalStateException("should not reach here, unknown child of GeneralName");
      }

      if (!isBase.equals(expBase)) {
        addViolation(failureMsg, "base of " + desc, isBase, expBase);
      }
    }
  } // method checkExtnNameConstraintsSubtrees

}
