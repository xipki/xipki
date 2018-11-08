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

package org.xipki.qa.ocsp.shell;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.xipki.ocsp.client.shell.BaseOcspStatusAction;
import org.xipki.qa.ValidationIssue;
import org.xipki.qa.ValidationResult;
import org.xipki.qa.ocsp.Occurrence;
import org.xipki.qa.ocsp.OcspCertStatus;
import org.xipki.qa.ocsp.OcspError;
import org.xipki.qa.ocsp.OcspQa;
import org.xipki.qa.ocsp.OcspResponseOption;
import org.xipki.qa.ocsp.shell.completer.CertStatusCompleter;
import org.xipki.qa.ocsp.shell.completer.OccurrenceCompleter;
import org.xipki.qa.ocsp.shell.completer.OcspErrorCompleter;
import org.xipki.security.IssuerHash;
import org.xipki.security.SecurityFactory;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.completer.HashAlgCompleter;
import org.xipki.shell.completer.SigAlgCompleter;
import org.xipki.util.DateUtil;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xiqa", name = "qa-ocsp-status", description = "request certificate status (QA)")
@Service
public class OcspQaStatusAction extends BaseOcspStatusAction {

  @Option(name = "--exp-error", description = "expected error")
  @Completion(OcspErrorCompleter.class)
  private String errorText;

  @Option(name = "--exp-status", multiValued = true, description = "expected status")
  @Completion(CertStatusCompleter.class)
  private List<String> statusTexts;

  @Option(name = "--rev-time", multiValued = true,
      description = "revocation time, UTC time of format yyyyMMddHHmmss")
  private List<String> revTimeTexts;

  @Option(name = "--exp-sig-alg", description = "expected signature algorithm")
  @Completion(SigAlgCompleter.class)
  private String sigAlg;

  @Option(name = "--no-sig-verify", description = "no verification of the signature")
  private Boolean noSigVerify = Boolean.FALSE;

  @Option(name = "--exp-nextupdate", description = "occurrence of nextUpdate")
  @Completion(OccurrenceCompleter.class)
  private String nextUpdateOccurrenceText = Occurrence.optional.name();

  @Option(name = "--exp-certhash",
      description = "occurrence of certHash, "
          + "will be set to forbidden for status unknown and issuerUnknown")
  @Completion(OccurrenceCompleter.class)
  private String certhashOccurrenceText = Occurrence.optional.name();

  @Option(name = "--exp-certhash-alg", description = "occurrence of certHash")
  @Completion(HashAlgCompleter.class)
  private String certhashAlg;

  @Option(name = "--exp-nonce", description = "occurrence of nonce")
  @Completion(OccurrenceCompleter.class)
  private String nonceOccurrenceText = Occurrence.optional.name();

  @Reference
  private SecurityFactory securityFactory;

  private OcspQa ocspQa;

  private OcspError expectedOcspError;

  private Map<BigInteger, OcspCertStatus> expectedStatuses;

  private Map<BigInteger, Date> expecteRevTimes;

  private Occurrence expectedNextUpdateOccurrence;

  private Occurrence expectedCerthashOccurrence;

  private Occurrence expectedNonceOccurrence;

  @Override
  protected void checkParameters(X509Certificate respIssuer, List<BigInteger> serialNumbers,
      Map<BigInteger, byte[]> encodedCerts) throws Exception {
    ParamUtil.requireNonEmpty("serialNunmbers", serialNumbers);

    if (isBlank(errorText) && isEmpty(statusTexts)) {
      throw new IllegalArgumentException(
          "neither expError nor expStatus is set, this is not permitted");
    }

    if (isNotBlank(errorText) && isNotEmpty(statusTexts)) {
      throw new IllegalArgumentException(
          "both expError and expStatus are set, this is not permitted");
    }

    if (isNotBlank(errorText)) {
      expectedOcspError = OcspError.forName(errorText);
    }

    if (isNotEmpty(statusTexts)) {
      if (statusTexts.size() != serialNumbers.size()) {
        throw new IllegalArgumentException("number of expStatus is invalid: "
            + (statusTexts.size()) + ", it should be " + serialNumbers.size());
      }

      expectedStatuses = new HashMap<>();
      final int n = serialNumbers.size();

      for (int i = 0; i < n; i++) {
        String expectedStatusText = statusTexts.get(i);
        OcspCertStatus certStatus = OcspCertStatus.forName(expectedStatusText);
        expectedStatuses.put(serialNumbers.get(i), certStatus);
      }
    }

    if (isNotEmpty(revTimeTexts)) {
      if (revTimeTexts.size() != serialNumbers.size()) {
        throw new IllegalArgumentException("number of revTimes is invalid: "
            + (revTimeTexts.size()) + ", it should be " + serialNumbers.size());
      }

      expecteRevTimes = new HashMap<>();
      final int n = serialNumbers.size();

      for (int i = 0; i < n; i++) {
        Date revTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(revTimeTexts.get(i));
        expecteRevTimes.put(serialNumbers.get(i), revTime);
      }
    }

    expectedCerthashOccurrence = Occurrence.forName(certhashOccurrenceText);
    expectedNextUpdateOccurrence = Occurrence.forName(nextUpdateOccurrenceText);
    expectedNonceOccurrence = Occurrence.forName(nonceOccurrenceText);
  } // method checkParameters

  @Override
  protected Object processResponse(OCSPResp response, X509Certificate respIssuer,
      IssuerHash issuerHash, List<BigInteger> serialNumbers, Map<BigInteger, byte[]> encodedCerts)
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

    if (ocspQa == null) {
      ocspQa = new OcspQa(securityFactory);
    }

    ValidationResult result = ocspQa.checkOcsp(response, issuerHash, serialNumbers, encodedCerts,
        expectedOcspError, expectedStatuses, expecteRevTimes, responseOption, noSigVerify);

    StringBuilder sb = new StringBuilder(50);
    sb.append("OCSP response is ");
    sb.append(result.isAllSuccessful() ? "valid" : "invalid");

    if (verbose.booleanValue()) {
      for (ValidationIssue issue : result.getValidationIssues()) {
        sb.append("\n");
        format(issue, "    ", sb);
      }
    }

    println(sb.toString());
    if (!result.isAllSuccessful()) {
      throw new CmdFailure("OCSP response is invalid");
    }
    return null;
  } // method processResponse

  static void format(ValidationIssue issue, String prefix, StringBuilder sb) {
    sb.append(prefix).append(issue.getCode()).append(", ").append(issue.getDescription());
    sb.append(", ").append(issue.isFailed() ? "failed" : "successful");
    if (issue.getFailureMessage() != null) {
      sb.append(", ").append(issue.getFailureMessage());
    }
  }

}
