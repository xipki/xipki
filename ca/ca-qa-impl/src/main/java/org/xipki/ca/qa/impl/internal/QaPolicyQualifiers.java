/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.ca.qa.impl.internal;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.xml.bind.JAXBElement;

import org.xipki.ca.certprofile.x509.jaxb.CertificatePolicyInformationType.PolicyQualifiers;
import org.xipki.ca.qa.impl.internal.QaPolicyQualifierInfo.QaCPSUriPolicyQualifier;
import org.xipki.ca.qa.impl.internal.QaPolicyQualifierInfo.QaUserNoticePolicyQualifierInfo;
import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class QaPolicyQualifiers
{
    private final List<QaPolicyQualifierInfo> policyQualifiers;
    public QaPolicyQualifiers(
            final PolicyQualifiers jaxb)
    {
        ParamChecker.assertNotNull("jaxb", jaxb);

        List<QaPolicyQualifierInfo> list = new LinkedList<>();

        List<JAXBElement<String>> elements = jaxb.getCpsUriOrUserNotice();
        for(JAXBElement<String> element : elements)
        {
            String value = element.getValue();
            String localPart = element.getName().getLocalPart();

            QaPolicyQualifierInfo info;
            if("cpsUri".equals(localPart))
            {
                info = new QaCPSUriPolicyQualifier(value);
            } else if("userNotice".equals(localPart))
            {
                info = new QaUserNoticePolicyQualifierInfo(value);
            } else
            {
                throw new RuntimeException("should not reach here, unknown child of PolicyQualifiers " + localPart);
            }
            list.add(info);
        }

        this.policyQualifiers = Collections.unmodifiableList(list);
    }

    public List<QaPolicyQualifierInfo> getPolicyQualifiers()
    {
        return policyQualifiers;
    }

}
