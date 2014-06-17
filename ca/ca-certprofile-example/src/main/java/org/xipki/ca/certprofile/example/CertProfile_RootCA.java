/*
 * Copyright (c) 2014 xipki.org
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
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.api.profile.AbstractCACertProfile;
import org.xipki.ca.api.profile.BadCertTemplateException;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.KeyUsage;

public class CertProfile_RootCA extends AbstractCACertProfile
{
    private final Map<ASN1ObjectIdentifier, ExtensionOccurrence> extensionOccurences;

    public CertProfile_RootCA()
    {
        // Extensions
        Map<ASN1ObjectIdentifier, ExtensionOccurrence> _extensionOccurences = new HashMap<>();
        _extensionOccurences.put(Extension.keyUsage, ExtensionOccurrence.CRITICAL_REQUIRED);
        _extensionOccurences.put(Extension.basicConstraints, ExtensionOccurrence.CRITICAL_REQUIRED);
        extensionOccurences = Collections.unmodifiableMap(_extensionOccurences);
    }

    @Override
    public ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier()
    {
        return null;
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
    protected Integer getPathLenBasicConstraint()
    {
        return null;
    }

    @Override
    protected Set<KeyUsage> getKeyUsage()
    {
        return keyUsages;
    }

    @Override
    protected Map<ASN1ObjectIdentifier, ExtensionOccurrence> getAdditionalExtensionOccurences()
    {
        return extensionOccurences;
    }
}
