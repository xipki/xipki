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

package org.xipki.ocsp.qa.shell;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.StringTokenizer;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.RequestResponseDebug;
import org.xipki.common.RequestResponsePair;
import org.xipki.common.qa.ValidationResult;
import org.xipki.common.util.DateUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.console.karaf.completer.DirPathCompleter;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.console.karaf.completer.HashAlgCompleter;
import org.xipki.console.karaf.completer.SigAlgCompleter;
import org.xipki.ocsp.client.api.OcspRequestor;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.ocsp.client.shell.OcspStatusAction;
import org.xipki.ocsp.qa.Occurrence;
import org.xipki.ocsp.qa.OcspCertStatus;
import org.xipki.ocsp.qa.OcspQa;
import org.xipki.ocsp.qa.OcspResponseOption;
import org.xipki.ocsp.qa.shell.completer.OccurrenceCompleter;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgoType;
import org.xipki.security.IssuerHash;
import org.xipki.security.SecurityFactory;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xiqa", name = "batch-ocsp-status",
        description = "request status of certificates (QA)")
@Service
public class BatchOcspQaStatusCmd extends OcspStatusAction {

    private static final Logger LOG = LoggerFactory.getLogger(BatchOcspQaStatusCmd.class);

    @Option(name = "--resp-issuer",
            description = "certificate file of the responder's issuer")
    @Completion(FilePathCompleter.class)
    private String respIssuerFile;

    @Option(name = "--url", required = true,
            description = "OCSP responder URL\n(required)")
    private String serverUrlStr;

    @Option(name = "--sn-file", required = true,
            description =
                "file containing the serial number and revocation information\n(required)")
    @Completion(FilePathCompleter.class)
    private String snFile;

    @Option(name = "--out-dir", required = true,
            description = "folder to save the request and response")
    @Completion(DirPathCompleter.class)
    private String outDirStr;

    @Option(name = "--save-req",
            description = "where to save the request")
    @Completion(FilePathCompleter.class)
    private Boolean saveReq = Boolean.FALSE;

    @Option(name = "--save-resp",
            description = "where to save the request")
    @Completion(FilePathCompleter.class)
    private Boolean saveResp = Boolean.FALSE;

    @Option(name = "--exp-sig-alg",
            description = "expected signature algorithm")
    @Completion(SigAlgCompleter.class)
    private String sigAlg;

    @Option(name = "--exp-nextupdate",
            description = "occurrence of nextUpdate")
    @Completion(OccurrenceCompleter.class)
    private String nextUpdateOccurrenceText = Occurrence.optional.name();

    @Option(name = "--exp-certhash",
            description = "occurrence of certHash, "
                    + "will be set to forbidden for status unknown and issuerUnknown")
    @Completion(OccurrenceCompleter.class)
    private String certhashOccurrenceText = Occurrence.optional.name();

    @Option(name = "--exp-certhash-alg",
            description = "occurrence of certHash")
    @Completion(HashAlgCompleter.class)
    private String certhashAlg;

    @Option(name = "--exp-nonce",
            description = "occurrence of nonce")
    @Completion(OccurrenceCompleter.class)
    private String nonceOccurrenceText = Occurrence.optional.name();

    @Reference
    private SecurityFactory securityFactory;

    @Reference
    private OcspRequestor requestor;

    private Occurrence expectedCerthashOccurrence;

    private Occurrence expectedNextUpdateOccurrence;

    private Occurrence expectedNonceOccurrence;

    @Override
    protected final Object execute0() throws Exception {
        expectedCerthashOccurrence = Occurrence.forName(certhashOccurrenceText);
        expectedNextUpdateOccurrence = Occurrence.forName(nextUpdateOccurrenceText);
        expectedNonceOccurrence = Occurrence.forName(nonceOccurrenceText);

        X509Certificate issuerCert = X509Util.parseCert(issuerCertFile);

        X509Certificate respIssuer = null;
        if (respIssuerFile != null) {
            respIssuer = X509Util.parseCert(IoUtil.expandFilepath(respIssuerFile));
        }

        RequestOptions requestOptions = getRequestOptions();

        IssuerHash issuerHash = new IssuerHash(
                HashAlgoType.getNonNullHashAlgoType(requestOptions.hashAlgorithmId()),
                Certificate.getInstance(issuerCert.getEncoded()));

        File outDir = new File(outDirStr);
        File messageDir = new File(outDir, "messages");
        messageDir.mkdirs();

        OutputStream resultOut = new FileOutputStream(new File(outDir, "overview.txt"));
        BufferedReader snReader = new BufferedReader(new FileReader(snFile));

        try {
            URL serverUrl = new URL(serverUrlStr);

            OcspQa ocspQa = new OcspQa(securityFactory);

            // Content of a line:
            // <hex-encoded serial number>[,<reason code>,<revocation time in epoch seconds>]
            int lineNo = 0;
            String line;

            byte[] NEWLINE = new byte[]{'\n'};

            while ((line = snReader.readLine()) != null) {
                lineNo++;
                line = line.trim();

                if (line.startsWith("#") || line.isEmpty()) {
                    resultOut.write(line.getBytes());
                    resultOut.write(NEWLINE);
                    continue;
                }

                String resultText = lineNo + ": " + line + ": ";
                try {
                    ValidationResult result = processOcspQuery(ocspQa, line, messageDir, serverUrl,
                            respIssuer, issuerCert, issuerHash, requestOptions);
                    resultText += result.isAllSuccessful() ? "valid" : "invalid";
                } catch (Throwable th) {
                    LogUtil.error(LOG, th);
                    resultText += "error - " + th.getMessage();
                }

                println(resultText);
                resultOut.write(resultText.getBytes());
                resultOut.write(NEWLINE);
            }

            // unknown serial number
            lineNo++;
            SecureRandom random = new SecureRandom();
            byte[] bytes = new byte[16];
            random.nextBytes(bytes);
            bytes[0] = (byte) (0x7F & bytes[0]);
            BigInteger serialNumber = new BigInteger(bytes);

            String resultText = lineNo + ": " + serialNumber.toString(16) + ",unknown: ";
            try {
                ValidationResult result = processOcspQuery(ocspQa, serialNumber,
                        OcspCertStatus.unknown, null, messageDir, serverUrl,
                        respIssuer, issuerCert, issuerHash, requestOptions);
                resultText += result.isAllSuccessful() ? "valid" : "invalid";
            } catch (Throwable th) {
                LogUtil.error(LOG, th);
                resultText += "error - " + th.getMessage();
            }

            println(resultText);
            resultOut.write(resultText.getBytes());
            resultOut.write(NEWLINE);
        } finally {
            snReader.close();
            resultOut.close();
        }

        return null;
    } // method execute0

    private ValidationResult processOcspQuery(OcspQa ocspQa, String line,
            File messageDir, URL serverUrl, X509Certificate respIssuer, X509Certificate issuerCert,
            IssuerHash issuerHash, RequestOptions requestOptions) throws Exception {
        StringTokenizer tokens = new StringTokenizer(line, ",;:");

        int count = tokens.countTokens();
        BigInteger serialNumber;
        OcspCertStatus status = null;
        Date revTime = null;
        try {
            serialNumber = new BigInteger(tokens.nextToken(), 16);

            if (count > 1) {
                String token = tokens.nextToken();
                if ("unknown".equalsIgnoreCase(token)) {
                    status = OcspCertStatus.unknown;
                } else if ("good".equalsIgnoreCase(token)) {
                    status = OcspCertStatus.good;
                } else {
                    CrlReason reason = CrlReason.forReasonCode(Integer.parseInt(token));
                    switch (reason) {
                        case AA_COMPROMISE:
                            status = OcspCertStatus.aACompromise;
                            break;
                        case CA_COMPROMISE:
                            status = OcspCertStatus.cACompromise;
                            break;
                        case AFFILIATION_CHANGED:
                            status = OcspCertStatus.affiliationChanged;
                            break;
                        case CERTIFICATE_HOLD:
                            status = OcspCertStatus.certificateHold;
                            break;
                        case CESSATION_OF_OPERATION:
                            status = OcspCertStatus.cessationOfOperation;
                            break;
                        case KEY_COMPROMISE:
                            status = OcspCertStatus.keyCompromise;
                            break;
                        case PRIVILEGE_WITHDRAWN:
                            status = OcspCertStatus.privilegeWithdrawn;
                            break;
                        case SUPERSEDED:
                            status = OcspCertStatus.superseded;
                            break;
                        case UNSPECIFIED:
                            status = OcspCertStatus.unspecified;
                            break;
                        default:
                            throw new Exception("invalid reason");
                    }
                }
            } else {
                status = OcspCertStatus.good;
            }

            if (count > 2 && status != OcspCertStatus.good && status != OcspCertStatus.unknown) {
                revTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(tokens.nextToken());
            }
        } catch (Exception ex) {
            LOG.warn("Could not parse line '{}'", line);
            throw new IllegalArgumentException("illegal line");
        }

        return processOcspQuery(ocspQa, serialNumber, status, revTime, messageDir, serverUrl,
                respIssuer, issuerCert, issuerHash, requestOptions);
    }

    private ValidationResult processOcspQuery(OcspQa ocspQa, BigInteger serialNumber,
            OcspCertStatus status, Date revTime,
            File messageDir, URL serverUrl, X509Certificate respIssuer, X509Certificate issuerCert,
            IssuerHash issuerHash, RequestOptions requestOptions) throws Exception {
        RequestResponseDebug debug = null;
        if (saveReq || saveResp) {
            debug = new RequestResponseDebug();
        }

        OCSPResp response;
        try {
            response = requestor.ask(issuerCert, serialNumber, serverUrl, requestOptions, debug);
        } finally {
            if (debug != null && debug.size() > 0) {
                RequestResponsePair reqResp = debug.get(0);
                String filename = serialNumber.toString(16);

                if (saveReq) {
                    byte[] bytes = reqResp.request();
                    if (bytes != null) {
                        IoUtil.save(new File(messageDir, filename + ".req"), bytes);
                    }
                }

                if (saveResp) {
                    byte[] bytes = reqResp.response();
                    if (bytes != null) {
                        IoUtil.save(new File(messageDir, filename + ".resp"), bytes);
                    }
                }
            } // end if
        } // end finally

        // analyze the result
        OcspResponseOption responseOption = new OcspResponseOption();
        responseOption.setNextUpdateOccurrence(expectedNextUpdateOccurrence);
        responseOption.setCerthashOccurrence(expectedCerthashOccurrence);
        responseOption.setNonceOccurrence(expectedNonceOccurrence);
        responseOption.setRespIssuer(respIssuer);
        responseOption.setSignatureAlgName(sigAlg);
        if (isNotBlank(certhashAlg)) {
            responseOption.setCerthashAlgId(AlgorithmUtil.getHashAlg(certhashAlg));
        }

        return ocspQa.checkOcsp(response, issuerHash, serialNumber, null, null, status,
                responseOption, revTime);
    }

}
