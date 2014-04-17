/*
 * Copyright 2014 xipki.org
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

package lca.ca.profile.extension;

import java.util.List;

public class ExtensionConfs
{

    private boolean useSubjectKeyIdentifier = false;

    public void setUseSubjectKeyIdentifier(boolean useSubjectKeyIdentifier)
    {
        this.useSubjectKeyIdentifier = useSubjectKeyIdentifier;
    }

    public boolean isUseSubjectKeyIdentifier()
    {
        return useSubjectKeyIdentifier;
    }

    private boolean useAuthorityKeyIdentifier = false;

    public void setUseAuthorityKeyIdentifier(boolean useAuthorityKeyIdentifier)
    {
        this.useAuthorityKeyIdentifier = useAuthorityKeyIdentifier;
    }

    public boolean isUseAuthorityKeyIdentifier()
    {
        return useAuthorityKeyIdentifier;
    }

    private KeyUsageExtension keyUsage;

    public void setKeyUsage(KeyUsageExtension keyUsage)
    {
        this.keyUsage = keyUsage;
    }

    public KeyUsageExtension getKeyUsage()
    {
        return keyUsage;
    }

    private ExtendedKeyUsageExtension extendedKeyUsage;

    public void setExtendedKeyUsage(ExtendedKeyUsageExtension extendedKeyUsage)
    {
        this.extendedKeyUsage = extendedKeyUsage;
    }

    public ExtendedKeyUsageExtension getExtendedKeyUsage()
    {
        return extendedKeyUsage;
    }

    private AuthorityInformationAccessExtension authorityInformationAccess;

    public void setAuthorityInformationAccess(AuthorityInformationAccessExtension authorityInformationAccess)
    {
        this.authorityInformationAccess = authorityInformationAccess;
    }

    public AuthorityInformationAccessExtension getAuthorityInformationAccess()
    {
        return authorityInformationAccess;
    }

    private BasicConstraintsExtension basicConstraints;

    public void setBasicConstraints(BasicConstraintsExtension basicConstraints)
    {
        this.basicConstraints = basicConstraints;
    }

    public BasicConstraintsExtension getBasicConstraints()
    {
        return basicConstraints;
    }

    private CertificatePoliciesExtension certificatePolicies;

    public void setCertificatePolicies(CertificatePoliciesExtension certificatePolicies)
    {
        this.certificatePolicies = certificatePolicies;
    }

    public CertificatePoliciesExtension getCertificatePolicies()
    {
        return certificatePolicies;
    }

    private List<ConstantExtension> constantExtensions;

    public void setConstantExtensions(List<ConstantExtension> constantExtensions)
    {
        this.constantExtensions = constantExtensions;
    }

    public List<ConstantExtension> getConstantExtensions()
    {
        return constantExtensions;
    }

}
