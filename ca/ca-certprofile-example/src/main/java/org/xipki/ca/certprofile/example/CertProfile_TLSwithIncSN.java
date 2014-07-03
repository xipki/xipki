/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.certprofile.example;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.api.profile.AbstractEECertProfile;
import org.xipki.ca.api.profile.BadCertTemplateException;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.KeyUsage;
import org.xipki.security.common.ObjectIdentifiers;

/**
 * @author Lijun Liao
 */

public class CertProfile_TLSwithIncSN extends AbstractEECertProfile
{
    private final Set<KeyUsage> keyUsages;
    private final Set<ASN1ObjectIdentifier> extendedKeyUsages;
    private final Map<ASN1ObjectIdentifier, ExtensionOccurrence> extensionOccurences;

    public CertProfile_TLSwithIncSN()
    {
        // KeyUsages
        Set<KeyUsage> _keyUsages = new HashSet<>();
        _keyUsages.add(KeyUsage.digitalSignature);
        _keyUsages.add(KeyUsage.keyEncipherment);
        keyUsages = Collections.unmodifiableSet(_keyUsages);

        // extended KeyUsages
        Set<ASN1ObjectIdentifier> _extendedKeyUsages = new HashSet<>();
        _extendedKeyUsages.add(ObjectIdentifiers.id_kp_clientAuth);
        _extendedKeyUsages.add(ObjectIdentifiers.id_kp_serverAuth);
        extendedKeyUsages = Collections.unmodifiableSet(_extendedKeyUsages);

        // Extensions
        Map<ASN1ObjectIdentifier, ExtensionOccurrence> _extensionOccurences = new HashMap<>();
        _extensionOccurences.put(Extension.keyUsage, ExtensionOccurrence.CRITICAL_REQUIRED);
        _extensionOccurences.put(Extension.basicConstraints, ExtensionOccurrence.CRITICAL_REQUIRED);
        _extensionOccurences.put(Extension.extendedKeyUsage, ExtensionOccurrence.NONCRITICAL_REQUIRED);
        extensionOccurences = Collections.unmodifiableMap(_extensionOccurences);

    }

    @Override
    public Integer getValidity()
    {
        return 5 * 365;
    }

    @Override
    protected void checkSubjectContent(X500Name requestedSubject)
    throws BadCertTemplateException
    {
    }

    @Override
    protected Set<KeyUsage> getKeyUsage()
    {
        return keyUsages;
    }

    @Override
    protected Set<ASN1ObjectIdentifier> getExtendedKeyUsages()
    {
        return extendedKeyUsages;
    }

    @Override
    protected Map<ASN1ObjectIdentifier, ExtensionOccurrence> getAdditionalExtensionOccurences()
    {
        return extensionOccurences;
    }

    @Override
    public boolean incSerialNumberIfSubjectExists()
    {
        return true;
    }

}
