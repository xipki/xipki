/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ca.server.mgmt.shell.cert;

import java.util.Date;
import java.util.List;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.server.mgmt.api.CertListInfo;
import org.xipki.ca.server.mgmt.api.CertListOrderBy;
import org.xipki.ca.server.mgmt.shell.CaAction;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.CertListSortByCompleter;
import org.xipki.common.util.DateUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.IllegalCmdParamException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "list-cert",
        description = "show a list of certificates")
@Service
public class ListCertCmd extends CaAction {

    @Option(name = "--ca",
            required = true,
            description = "CA name\n"
                    + "(required)")
    @Completion(CaNameCompleter.class)
    protected String caName;

    @Option(name = "--subject",
            description = "the subject pattern, * is allowed.")
    protected String subjectPatternS;

    @Option(name = "--valid-from",
            description = "start UTC time when the certificate is still valid, in form of"
                    + "yyyyMMdd or yyyyMMddHHmmss")
    private String validFromS;

    @Option(name = "--valid-to",
            description = "end UTC time when the certificate is still valid, in form of"
                    + "yyyMMdd or yyyyMMddHHmmss")
    private String validToS;

    @Option(name = "-n",
            description = "maximal number of entries (between 1 and 1000)")
    private int num = 1000;

    @Option(name = "--order",
            description = "by which the result is ordered")
    @Completion(CertListSortByCompleter.class)
    private String orderByS;

    /**
     * @return comma-separated serial numbers (in hex).
     */
    @Override
    protected Object execute0() throws Exception {
        Date validFrom = getDate(validFromS);
        Date validTo = getDate(validToS);
        X500Name subjectPattern = null;
        if (StringUtil.isNotBlank(subjectPatternS)) {
            subjectPattern = new X500Name(subjectPatternS);
        }

        CertListOrderBy orderBy = null;
        if (orderByS != null) {
            orderBy = CertListOrderBy.forValue(orderByS);
            if (orderBy == null) {
                throw new IllegalCmdParamException("invalid order '" + orderByS + "'");
            }
        }

        List<CertListInfo> certInfos = caManager.listCertificates(caName, subjectPattern, validFrom,
                validTo, orderBy, num);
        final int n = certInfos.size();
        if (n == 0) {
            println("found no certificate");
            return null;
        }

        println("     | serial               | notBefore      | notAfter       | subject");
        println("-----+----------------------+----------------+----------------+-----------------");
        for (int i = 0; i < n; i++) {
            CertListInfo info = certInfos.get(i);
            println(format(i + 1, info));
        }

        return null;
    }

    private String format(int index, CertListInfo info) {
        StringBuilder sb = new StringBuilder(300);
        sb.append(StringUtil.formatAccount(index, 4)).append(" | ");
        sb.append(StringUtil.formatText(info.serialNumber().toString(16), 20)).append(" | ");
        sb.append(DateUtil.toUtcTimeyyyyMMddhhmmss(info.notBefore())).append(" | ");
        sb.append(DateUtil.toUtcTimeyyyyMMddhhmmss(info.notAfter())).append(" | ");
        sb.append(info.subject());
        return sb.toString();
    }

    private Date getDate(String str) throws IllegalCmdParamException {
        if (str == null) {
            return null;
        }

        final int len = str.length();
        try {
            if (len == 8) {
                return DateUtil.parseUtcTimeyyyyMMdd(str);
            } else if (len == 14) {
                return DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
            } else {
                throw new IllegalCmdParamException("invalid time " + str);
            }
        } catch (IllegalArgumentException ex) {
            throw new IllegalCmdParamException("invalid time " + str + ": " + ex.getMessage(), ex);
        }
    }

}
