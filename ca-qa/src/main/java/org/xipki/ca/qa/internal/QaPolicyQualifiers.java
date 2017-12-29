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

import javax.xml.bind.JAXBElement;

import org.xipki.ca.certprofile.x509.jaxb.CertificatePolicyInformationType.PolicyQualifiers;
import org.xipki.ca.qa.internal.QaPolicyQualifierInfo.QaCpsUriPolicyQualifier;
import org.xipki.ca.qa.internal.QaPolicyQualifierInfo.QaUserNoticePolicyQualifierInfo;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class QaPolicyQualifiers {

    private final List<QaPolicyQualifierInfo> policyQualifiers;

    public QaPolicyQualifiers(PolicyQualifiers jaxb) {
        ParamUtil.requireNonNull("jaxb", jaxb);
        List<QaPolicyQualifierInfo> list = new LinkedList<>();
        List<JAXBElement<String>> elements = jaxb.getCpsUriOrUserNotice();
        for (JAXBElement<String> element : elements) {
            String value = element.getValue();
            String localPart = element.getName().getLocalPart();

            QaPolicyQualifierInfo info;
            if ("cpsUri".equals(localPart)) {
                info = new QaCpsUriPolicyQualifier(value);
            } else if ("userNotice".equals(localPart)) {
                info = new QaUserNoticePolicyQualifierInfo(value);
            } else {
                throw new RuntimeException(
                        "should not reach here, unknown child of PolicyQualifiers " + localPart);
            }
            list.add(info);
        }

        this.policyQualifiers = Collections.unmodifiableList(list);
    }

    public List<QaPolicyQualifierInfo> policyQualifiers() {
        return policyQualifiers;
    }

}
