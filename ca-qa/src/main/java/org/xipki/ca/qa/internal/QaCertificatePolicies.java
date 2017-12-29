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

package org.xipki.ca.qa.internal;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.xipki.ca.certprofile.x509.jaxb.CertificatePolicies;
import org.xipki.ca.certprofile.x509.jaxb.CertificatePolicyInformationType;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class QaCertificatePolicies extends QaExtension {

    public static class QaCertificatePolicyInformation {

        private final String policyId;

        private final QaPolicyQualifiers policyQualifiers;

        public QaCertificatePolicyInformation(CertificatePolicyInformationType jaxb) {
            ParamUtil.requireNonNull("jaxb", jaxb);
            this.policyId = jaxb.getPolicyIdentifier().getValue();
            this.policyQualifiers = (jaxb.getPolicyQualifiers() == null) ? null
                    : new QaPolicyQualifiers(jaxb.getPolicyQualifiers());
        }

        public String policyId() {
            return policyId;
        }

        public QaPolicyQualifiers policyQualifiers() {
            return policyQualifiers;
        }

    } // class QaCertificatePolicyInformation

    private final List<QaCertificatePolicyInformation> policyInformations;

    public QaCertificatePolicies(CertificatePolicies jaxb) {
        ParamUtil.requireNonNull("jaxb", jaxb);
        List<CertificatePolicyInformationType> types = jaxb.getCertificatePolicyInformation();
        List<QaCertificatePolicyInformation> list = new LinkedList<>();
        for (CertificatePolicyInformationType type : types) {
            list.add(new QaCertificatePolicyInformation(type));
        }

        this.policyInformations = Collections.unmodifiableList(list);
    }

    public List<QaCertificatePolicyInformation> policyInformations() {
        return policyInformations;
    }

    public QaCertificatePolicyInformation policyInformation(String policyId) {
        ParamUtil.requireNonBlank("policyId", policyId);
        for (QaCertificatePolicyInformation entry : policyInformations) {
            if (entry.policyId().equals(policyId)) {
                return entry;
            }
        }

        return null;
    }

}
