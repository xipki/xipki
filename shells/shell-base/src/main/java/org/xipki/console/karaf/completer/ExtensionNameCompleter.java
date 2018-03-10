/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.console.karaf.completer;

import java.util.LinkedList;
import java.util.List;

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.AbstractEnumCompleter;
import org.xipki.security.ObjectIdentifiers;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Service
public class ExtensionNameCompleter extends AbstractEnumCompleter {

  public ExtensionNameCompleter() {
    List<ASN1ObjectIdentifier> oids = new LinkedList<>();
    oids.add(ObjectIdentifiers.id_extension_pkix_ocsp_nocheck);
    oids.add(ObjectIdentifiers.id_extension_admission);
    oids.add(Extension.auditIdentity);
    oids.add(Extension.authorityInfoAccess);
    oids.add(Extension.authorityKeyIdentifier);
    oids.add(Extension.basicConstraints);
    oids.add(Extension.biometricInfo);
    oids.add(Extension.certificateIssuer);
    oids.add(Extension.certificatePolicies);
    oids.add(Extension.cRLDistributionPoints);
    oids.add(Extension.cRLNumber);
    oids.add(Extension.deltaCRLIndicator);
    oids.add(Extension.extendedKeyUsage);
    oids.add(Extension.freshestCRL);
    oids.add(Extension.inhibitAnyPolicy);
    oids.add(Extension.instructionCode);
    oids.add(Extension.invalidityDate);
    oids.add(Extension.issuerAlternativeName);
    oids.add(Extension.issuingDistributionPoint);
    oids.add(Extension.keyUsage);
    oids.add(Extension.logoType);
    oids.add(Extension.nameConstraints);
    oids.add(Extension.noRevAvail);
    oids.add(Extension.policyConstraints);
    oids.add(Extension.policyMappings);
    oids.add(Extension.privateKeyUsagePeriod);
    oids.add(Extension.qCStatements);
    oids.add(Extension.reasonCode);
    oids.add(Extension.subjectAlternativeName);
    oids.add(Extension.subjectDirectoryAttributes);
    oids.add(Extension.subjectInfoAccess);
    oids.add(Extension.subjectKeyIdentifier);
    oids.add(Extension.targetInformation);
    oids.add(ObjectIdentifiers.id_pe_tlsfeature);

    StringBuilder enums = new StringBuilder();

    for (ASN1ObjectIdentifier oid : oids) {
      String name = ObjectIdentifiers.getName(oid);
      if (StringUtil.isBlank(name)) {
        name = oid.getId();
      }
      enums.append(name).append(",");
    }
    enums.deleteCharAt(enums.length() - 1);
    setTokens(enums.toString());
  }

}
