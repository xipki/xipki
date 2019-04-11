/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.ca.api.profile;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.Extn;

/**
 * TODO.
 * @author Lijun Liao
 */
public class ExtensionSpec {

  private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSION_TYPES;

  private static final Set<ASN1ObjectIdentifier> CA_CRITICAL_ONLY_EXTENSION_TYPES;

  private static final Set<ASN1ObjectIdentifier> NONCRITICAL_ONLY_EXTENSION_TYPES;

  private static final Set<ASN1ObjectIdentifier> CA_ONLY_EXTENSION_TYPES;

  private static final Set<ASN1ObjectIdentifier> NON_REQUEST_EXTENSION_TYPES;

  private static final Set<ASN1ObjectIdentifier> REQUIRED_CA_EXTENSION_TYPES;

  private static final Set<ASN1ObjectIdentifier> REQUIRED_EE_EXTENSION_TYPES;

  static {
    CRITICAL_ONLY_EXTENSION_TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
        Extension.keyUsage,
        Extension.policyMappings,
        Extension.nameConstraints,
        Extension.policyConstraints,
        Extension.inhibitAnyPolicy,
        ObjectIdentifiers.Extn.id_pe_tlsfeature)));

    CA_CRITICAL_ONLY_EXTENSION_TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
        Extension.basicConstraints)));

    NONCRITICAL_ONLY_EXTENSION_TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
        Extension.authorityKeyIdentifier,
        Extension.subjectKeyIdentifier,
        Extension.issuerAlternativeName,
        Extension.subjectDirectoryAttributes,
        Extension.freshestCRL,
        Extension.authorityInfoAccess,
        Extension.subjectInfoAccess,
        Extn.id_GMT_0015_ICRegistrationNumber,
        Extn.id_GMT_0015_IdentityCode,
        Extn.id_GMT_0015_InsuranceNumber,
        Extn.id_GMT_0015_OrganizationCode,
        Extn.id_GMT_0015_TaxationNumber)));

    CA_ONLY_EXTENSION_TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
        Extension.policyMappings,
        Extension.nameConstraints,
        Extension.policyConstraints,
        Extension.inhibitAnyPolicy)));

    NON_REQUEST_EXTENSION_TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
        Extension.subjectKeyIdentifier,
        Extension.authorityKeyIdentifier,
        Extension.issuerAlternativeName,
        Extension.cRLDistributionPoints,
        Extension.freshestCRL,
        Extension.basicConstraints,
        Extension.inhibitAnyPolicy)));

    REQUIRED_CA_EXTENSION_TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
        Extension.basicConstraints,
        Extension.subjectKeyIdentifier,
        Extension.keyUsage)));

    REQUIRED_EE_EXTENSION_TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
        Extension.authorityKeyIdentifier,
        Extension.subjectKeyIdentifier)));
  } // end static

  public static Set<ASN1ObjectIdentifier> getCaOnlyExtensionTypes() {
    return CA_ONLY_EXTENSION_TYPES;
  }

  public static Set<ASN1ObjectIdentifier> getCaCriticalOnlyExtensionTypes() {
    return CA_CRITICAL_ONLY_EXTENSION_TYPES;
  }

  public static Set<ASN1ObjectIdentifier> getCriticalOnlyExtensionTypes() {
    return CRITICAL_ONLY_EXTENSION_TYPES;
  }

  public static Set<ASN1ObjectIdentifier> getNonCriticalOnlyExtensionTypes() {
    return NONCRITICAL_ONLY_EXTENSION_TYPES;
  }

  public static Set<ASN1ObjectIdentifier> getNonRequestExtensionTypes() {
    return NON_REQUEST_EXTENSION_TYPES;
  }

  public static Set<ASN1ObjectIdentifier> getRequiredCaExtensionTypes() {
    return REQUIRED_CA_EXTENSION_TYPES;
  }

  public static Set<ASN1ObjectIdentifier> getRequiredEeExtensionTypes() {
    return REQUIRED_EE_EXTENSION_TYPES;
  }

}
