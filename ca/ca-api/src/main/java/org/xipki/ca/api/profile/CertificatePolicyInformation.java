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

package org.xipki.ca.api.profile;

import java.util.Collections;
import java.util.List;

import org.xipki.security.common.ParamChecker;

public class CertificatePolicyInformation
{
    private final String certPolicyId;
    private final List<CertificatePolicyQualifier> qualifiers;

    public CertificatePolicyInformation(String certPolicyId, List<CertificatePolicyQualifier> qualifiers)
    {
        ParamChecker.assertNotEmpty("certPolicyId", certPolicyId);
        this.certPolicyId = certPolicyId;
        this.qualifiers = qualifiers == null ? null : Collections.unmodifiableList(qualifiers);
    }

    public String getCertPolicyId() {
        return certPolicyId;
    }

    public List<CertificatePolicyQualifier> getQualifiers() {
        return qualifiers;
    }

}
