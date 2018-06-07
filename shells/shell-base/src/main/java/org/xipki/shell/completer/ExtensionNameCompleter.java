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

package org.xipki.shell.completer;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.karaf.shell.api.action.lifecycle.Service;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Service
public class ExtensionNameCompleter extends AbstractEnumCompleter {

  private static final Map<String, String> nameToIdMap = new HashMap<>();

  private static final Set<String> tokens;

  static {
    Map<String, String> map = new HashMap<>();
    map.put("admission", "1.3.36.8.3.3");
    map.put("auditIdentity", "1.3.6.1.5.5.7.1.4");
    map.put("authorityInfoAccess", "1.3.6.1.5.5.7.1.1");
    map.put("authorityKeyIdentifier", "2.5.29.35");
    map.put("basicConstraints", "2.5.29.19");
    map.put("biometricInfo", "1.3.6.1.5.5.7.1.2");
    map.put("cRLDistributionPoints", "2.5.29.31");
    map.put("cRLNumber", "2.5.29.20");
    map.put("certificateIssuer", "2.5.29.29");
    map.put("certificatePolicies", "2.5.29.32");
    map.put("deltaCRLIndicator", "2.5.29.27");
    map.put("extendedKeyUsage", "2.5.29.37");
    map.put("freshestCRL", "2.5.29.46");
    map.put("inhibitAnyPolicy", "2.5.29.54");
    map.put("instructionCode", "2.5.29.23");
    map.put("invalidityDate", "2.5.29.24");
    map.put("issuerAlternativeName", "2.5.29.18");
    map.put("issuingDistributionPoint", "2.5.29.28");
    map.put("keyUsage", "2.5.29.15");
    map.put("logoType", "1.3.6.1.5.5.7.1.12");
    map.put("nameConstraints", "2.5.29.30");
    map.put("noRevAvail", "2.5.29.56");
    map.put("ocspNocheck", "1.3.6.1.5.5.7.48.1.5");
    map.put("policyConstraints", "2.5.29.36");
    map.put("policyMappings", "2.5.29.33");
    map.put("privateKeyUsagePeriod", "2.5.29.16");
    map.put("qCStatements", "1.3.6.1.5.5.7.1.3");
    map.put("reasonCode", "2.5.29.21");
    map.put("subjectAlternativeName", "2.5.29.17");
    map.put("subjectDirectoryAttributes", "2.5.29.9");
    map.put("subjectInfoAccess", "1.3.6.1.5.5.7.1.11");
    map.put("subjectKeyIdentifier", "2.5.29.14");
    map.put("targetInformation", "2.5.29.55");
    map.put("tlsfeature", "1.3.6.1.5.5.7.1.24");

    tokens = new HashSet<>(map.keySet());
    for (String name : map.keySet()) {
      nameToIdMap.put(name.toLowerCase(), map.get(name));
    }
  }

  public ExtensionNameCompleter() {
    setTokens(tokens);
  }

  public static String getIdForExtensionName(String name) {
    return nameToIdMap.get(name.toLowerCase());
  }

}
