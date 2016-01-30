/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.console.karaf.completer;

import java.util.LinkedList;
import java.util.List;

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.AbstractEnumCompleter;
import org.xipki.security.api.ObjectIdentifiers;

/**
 * @author Lijun Liao
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
