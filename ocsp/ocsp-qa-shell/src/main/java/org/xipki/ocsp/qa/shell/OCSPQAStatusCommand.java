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

package org.xipki.ocsp.qa.shell;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.xipki.common.qa.UnexpectedResultException;
import org.xipki.common.qa.ValidationIssue;
import org.xipki.common.qa.ValidationResult;
import org.xipki.common.util.SecurityUtil;
import org.xipki.ocsp.client.shell.BaseOCSPStatusCommand;
import org.xipki.ocsp.qa.api.Occurrence;
import org.xipki.ocsp.qa.api.OcspCertStatus;
import org.xipki.ocsp.qa.api.OcspError;
import org.xipki.ocsp.qa.api.OcspQA;
import org.xipki.ocsp.qa.api.OcspResponseOption;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-qa", name = "ocsp-status", description="request certificate status (QA)")
public class OCSPQAStatusCommand extends BaseOCSPStatusCommand
{
    @Option(name = "-expError",
            description = "expected error")
    private String errorText;

    @Option(name = "-expStatus",
            multiValued = true,
            description = "expected status\n"
                    + "(multi-valued)")
    private List<String> statusTexts;

    @Option(name = "-expSigAlg",
            description = "expected signature algorithm")
    private String sigAlg;

    @Option(name = "-expNextupdate",
            description = "occurence of nextUpdate")
    private String nextUpdateOccurrenceText = Occurrence.optional.name();

    @Option(name = "-expCerthash",
            description = "occurence of certHash")
    private String certhashOccurrenceText = Occurrence.optional.name();

    @Option(name = "-expCerthashAlg",
            description = "occurence of certHash")
    private String certhashAlg;

    @Option(name = "-expNonce",
            description = "occurence of nonce")
    private String nonceOccurrenceText = Occurrence.optional.name();

    private OcspQA ocspQA;

    public void setOcspQA(OcspQA ocspQA)
    {
        this.ocspQA = ocspQA;
    }

    @Override
    protected void checkParameters(X509Certificate respIssuer,
            List<BigInteger> serialNumbers, Map<BigInteger, byte[]> encodedCerts)
    throws Exception
    {
        if(isBlank(errorText) && isEmpty(statusTexts))
        {
            throw new Exception("neither expError nor expStatus is set, this is not permitted");
        }

        if(isNotBlank(errorText) && isNotEmpty(statusTexts))
        {
            throw new Exception("both expError and expStatus are set, this is not permitted");
        }

        if(isNotEmpty(statusTexts))
        {
            if(statusTexts.size() != serialNumbers.size())
            {
                throw new Exception("number of expStatus is invalid: " + (statusTexts.size()) +
                        ", it should be " + serialNumbers.size());
            }
        }
    }

    @Override
    protected Object processResponse(OCSPResp response, X509Certificate respIssuer,
            X509Certificate issuer, List<BigInteger> serialNumbers,
            Map<BigInteger, byte[]> encodedCerts)
    throws Exception
    {
        OcspError expectedOcspError = null;
        if(isNotBlank(errorText))
        {
            expectedOcspError = OcspError.getOCSPError(errorText);
        }

        Map<BigInteger, OcspCertStatus> expectedStatuses = null;
        if(isNotEmpty(statusTexts))
        {
            expectedStatuses = new HashMap<>();
            final int n = serialNumbers.size();

            for(int i = 0; i < n; i++)
            {
                String expectedStatusText = statusTexts.get(i);
                expectedStatuses.put(serialNumbers.get(i),
                        OcspCertStatus.getCertStatus(expectedStatusText));
            }
        }

        OcspResponseOption responseOption = new OcspResponseOption();
        responseOption.setNextUpdateOccurrence(
                Occurrence.getOccurrence(nextUpdateOccurrenceText));
        responseOption.setCerthashOccurrence(
                Occurrence.getOccurrence(certhashOccurrenceText));
        responseOption.setNonceOccurrence(
                Occurrence.getOccurrence(nonceOccurrenceText));
        responseOption.setRespIssuer(respIssuer);
        responseOption.setSignatureAlgName(sigAlg);
        if(isNotBlank(certhashAlg))
        {
            responseOption.setCerthashAlgId(SecurityUtil.getHashAlg(certhashAlg));
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
        sb.append(result.isAllSuccessful()? "valid" : "invalid");

        if(verbose.booleanValue())
        {
            for(ValidationIssue issue : result.getValidationIssues())
            {
                sb.append("\n");
                format(issue, "    ", sb);
            }
        }

        out(sb.toString());
        if(result.isAllSuccessful() == false)
        {
            throw new UnexpectedResultException("OCSP response is invalid");
        }
        return null;
    }

    private static void format(ValidationIssue issue, String prefix, StringBuilder sb)
    {
        sb.append(prefix);
        sb.append(issue.getCode());
        sb.append(", ").append(issue.getDescription());
        sb.append(", ").append(issue.isFailed() ? "failed" : "successful");
        if(issue.getMessage() != null)
        {
            sb.append(", ").append(issue.getMessage());
        }
    }

}
