/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.server.mgmt.shell.cert;

import java.util.Date;
import java.util.List;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.commons.common.util.DateUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.pki.ca.server.mgmt.api.CertListInfo;
import org.xipki.pki.ca.server.mgmt.api.CertListSortBy;
import org.xipki.pki.ca.server.mgmt.shell.CaCommandSupport;
import org.xipki.pki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.pki.ca.server.mgmt.shell.completer.CertListSortByCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-ca", name = "list-cert",
        description = "show a list of certificates")
@Service
public class ListCertCmd extends CaCommandSupport {

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

    @Option(name = "--sort",
            description = "by which the result is sorted")
    @Completion(CertListSortByCompleter.class)
    private String sortByS;

    /**
     * @return comma-separated serial numbers (in hex).
     */
    @Override
    protected Object doExecute() throws Exception {
        Date validFrom = getDate(validFromS);
        Date validTo = getDate(validToS);
        X500Name subjectPattern = null;
        if (StringUtil.isNotBlank(subjectPatternS)) {
            subjectPattern = new X500Name(subjectPatternS);
        }

        CertListSortBy sortBy = null;
        if (sortByS != null) {
            sortBy = CertListSortBy.forValue(sortByS);
            if (sortBy == null) {
                throw new IllegalCmdParamException("invalid sort '" + sortByS + "'");
            }
        }

        List<CertListInfo> certInfos = caManager.listCertificates(caName, subjectPattern, validFrom,
                validTo, sortBy, num);
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
        sb.append(StringUtil.formatText(info.getSerialNumber().toString(16), 20)).append(" | ");
        sb.append(DateUtil.toUtcTimeyyyyMMddhhmmss(info.getNotBefore())).append(" | ");
        sb.append(DateUtil.toUtcTimeyyyyMMddhhmmss(info.getNotAfter())).append(" | ");
        sb.append(info.getSubject());
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
