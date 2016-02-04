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

package org.xipki.pki.ocsp.qa.shell;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.xipki.commons.common.qa.ValidationIssue;
import org.xipki.commons.common.qa.ValidationResult;
import org.xipki.commons.console.karaf.CmdFailure;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.console.karaf.completer.HashAlgCompleter;
import org.xipki.commons.console.karaf.completer.SigAlgCompleter;
import org.xipki.commons.security.api.util.AlgorithmUtil;
import org.xipki.pki.ocsp.client.shell.BaseOCSPStatusCommandSupport;
import org.xipki.pki.ocsp.qa.api.Occurrence;
import org.xipki.pki.ocsp.qa.api.OcspCertStatus;
import org.xipki.pki.ocsp.qa.api.OcspError;
import org.xipki.pki.ocsp.qa.api.OcspQA;
import org.xipki.pki.ocsp.qa.api.OcspResponseOption;
import org.xipki.pki.ocsp.qa.shell.completer.CertStatusCompleter;
import org.xipki.pki.ocsp.qa.shell.completer.OccurrenceCompleter;
import org.xipki.pki.ocsp.qa.shell.completer.OcspErrorCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-qa", name = "ocsp-status",
        description = "request certificate status (QA)")
@Service
public class OCSPQAStatusCmd extends BaseOCSPStatusCommandSupport {

    @Option(name = "--exp-error",
            description = "expected error")
    @Completion(OcspErrorCompleter.class)
    private String errorText;

    @Option(name = "--exp-status",
            multiValued = true,
            description = "expected status\n"
                    + "(multi-valued)")
    @Completion(CertStatusCompleter.class)
    private List<String> statusTexts;

    @Option(name = "--exp-sig-alg",
            description = "expected signature algorithm")
    @Completion(SigAlgCompleter.class)
    private String sigAlg;

    @Option(name = "--exp-nextupdate",
            description = "occurence of nextUpdate")
    @Completion(OccurrenceCompleter.class)
    private String nextUpdateOccurrenceText = Occurrence.optional.name();

    @Option(name = "--exp-certhash",
            description = "occurence of certHash")
    @Completion(OccurrenceCompleter.class)
    private String certhashOccurrenceText = Occurrence.optional.name();

    @Option(name = "--exp-certhash-alg",
            description = "occurence of certHash")
    @Completion(HashAlgCompleter.class)
    private String certhashAlg;

    @Option(name = "--exp-nonce",
            description = "occurence of nonce")
    @Completion(OccurrenceCompleter.class)
    private String nonceOccurrenceText = Occurrence.optional.name();

    @Reference
    private OcspQA ocspQA;

    private OcspError expectedOcspError;

    private Map<BigInteger, OcspCertStatus> expectedStatuses = null;

    private Occurrence expectedNextUpdateOccurrence;

    private Occurrence expectedCerthashOccurrence;

    private Occurrence expectedNonceOccurrence;

    @Override
    protected void checkParameters(
            final X509Certificate respIssuer,
            final List<BigInteger> serialNumbers,
            final Map<BigInteger, byte[]> encodedCerts)
    throws Exception {
        if (isBlank(errorText) && isEmpty(statusTexts)) {
            throw new IllegalArgumentException(
                    "neither expError nor expStatus is set, this is not permitted");
        }

        if (isNotBlank(errorText) && isNotEmpty(statusTexts)) {
            throw new IllegalArgumentException(
                    "both expError and expStatus are set, this is not permitted");
        }

        if (isNotBlank(errorText)) {
            expectedOcspError = OcspError.getInstance(errorText);
            if (expectedOcspError == null) {
                throw new IllegalArgumentException("invalid OCSP error status '" + errorText + "'");
            }
        }

        if (isNotEmpty(statusTexts)) {
            if (statusTexts.size() != serialNumbers.size()) {
                throw new IllegalArgumentException("number of expStatus is invalid: "
                        + (statusTexts.size())
                        + ", it should be " + serialNumbers.size());
            }

            expectedStatuses = new HashMap<>();
            final int n = serialNumbers.size();

            for (int i = 0; i < n; i++) {
                String expectedStatusText = statusTexts.get(i);
                OcspCertStatus certStatus = OcspCertStatus.getInstance(expectedStatusText);
                if (certStatus == null) {
                    throw new IllegalArgumentException(
                            "invalid cert status '" + expectedStatusText + "'");
                }
                expectedStatuses.put(serialNumbers.get(i), certStatus);
            }
        }

        expectedCerthashOccurrence = getOccurrence(certhashOccurrenceText);
        expectedNextUpdateOccurrence = getOccurrence(nextUpdateOccurrenceText);
        expectedNonceOccurrence = getOccurrence(nonceOccurrenceText);
    } // method checkParameters

    @Override
    protected Object processResponse(
            final OCSPResp response,
            final X509Certificate respIssuer,
            final X509Certificate issuer,
            final List<BigInteger> serialNumbers,
            final Map<BigInteger, byte[]> encodedCerts)
    throws Exception {
        OcspResponseOption responseOption = new OcspResponseOption();
        responseOption.setNextUpdateOccurrence(expectedNextUpdateOccurrence);
        responseOption.setCerthashOccurrence(expectedCerthashOccurrence);
        responseOption.setNonceOccurrence(expectedNonceOccurrence);
        responseOption.setRespIssuer(respIssuer);
        responseOption.setSignatureAlgName(sigAlg);
        if (isNotBlank(certhashAlg)) {
            responseOption.setCerthashAlgId(AlgorithmUtil.getHashAlg(certhashAlg));
        }

        ValidationResult result = ocspQA.checkOCSP(response,
                issuer,
                serialNumbers,
                encodedCerts,
                expectedOcspError,
                expectedStatuses,
                responseOption);

        StringBuilder sb = new StringBuilder(50);
        sb.append("OCSP response is ");
        String txt = result.isAllSuccessful()
                ? "valid"
                : "invalid";
        sb.append(txt);

        if (verbose.booleanValue()) {
            for (ValidationIssue issue : result.getValidationIssues()) {
                sb.append("\n");
                format(issue, "    ", sb);
            }
        }

        out(sb.toString());
        if (!result.isAllSuccessful()) {
            throw new CmdFailure("OCSP response is invalid");
        }
        return null;
    } // method processResponse

    private static void format(
            final ValidationIssue issue,
            final String prefix,
            final StringBuilder sb) {
        sb.append(prefix);
        sb.append(issue.getCode());
        sb.append(", ").append(issue.getDescription());
        sb.append(", ");
        String txt = issue.isFailed()
                ? "failed"
                : "successful";
        sb.append(txt);
        if (issue.getMessage() != null) {
            sb.append(", ").append(issue.getMessage());
        }
    }

    private static Occurrence getOccurrence(
            final String text)
    throws IllegalCmdParamException {
        Occurrence ret = Occurrence.getInstance(text);
        if (ret == null) {
            throw new IllegalCmdParamException("invalid occurrence '" + text + "'");
        }
        return ret;
    }

}
