// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.client.OcspRequestor;
import org.xipki.ocsp.client.RequestOptions;
import org.xipki.ocsp.client.shell.OcspActions.BaseOcspStatusAction;
import org.xipki.ocsp.client.shell.OcspActions.CommonOcspStatusAction;
import org.xipki.qa.BigIntegerRange;
import org.xipki.qa.FileBigIntegerIterator;
import org.xipki.qa.RangeBigIntegerIterator;
import org.xipki.qa.ValidationIssue;
import org.xipki.qa.ValidationResult;
import org.xipki.qa.ocsp.OcspBenchmark;
import org.xipki.qa.ocsp.OcspCertStatus;
import org.xipki.qa.ocsp.OcspError;
import org.xipki.qa.ocsp.OcspQa;
import org.xipki.qa.ocsp.OcspResponseOption;
import org.xipki.security.CrlReason;
import org.xipki.security.IssuerHash;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.DateUtil;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.RandomUtil;
import org.xipki.util.ReqRespDebug;
import org.xipki.util.ReqRespDebug.ReqRespPair;
import org.xipki.util.StringUtil;
import org.xipki.util.TripleState;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * Actions of QA for OCSP.
 *
 * @author Lijun Liao (xipki)
 */

public class QaOcspActions {

  @Command(scope = "xiqa", name = "batch-ocsp-status",
      description = "batch request status of certificates (QA)")
  @Service
  public static class BatchOcspQaStatusAction extends CommonOcspStatusAction {

    private static final Logger LOG = LoggerFactory.getLogger(BatchOcspQaStatusAction.class);

    private static final String FILE_SEP = File.separator;

    @Option(name = "--resp-issuer", description = "certificate file of the responder's issuer")
    @Completion(FileCompleter.class)
    private String respIssuerFile;

    @Option(name = "--url", required = true, description = "OCSP responder URL")
    private String serverUrlStr;

    @Option(name = "--sn-file", required = true,
        description = "file containing the serial number and revocation information"
            + "\nEach line starts with # for comment or is of following format"
            + "\nserial-number[,status[,revocation-time]]")
    @Completion(FileCompleter.class)
    private String snFile;

    @Option(name = "--hex", description = "serial number without prefix is hex number")
    private Boolean hex = Boolean.FALSE;

    @Option(name = "--out-dir", required = true, description = "folder to save the request and response")
    @Completion(Completers.DirCompleter.class)
    private String outDirStr;

    @Option(name = "--save-req", description = "whether to save the request")
    private Boolean saveReq = Boolean.FALSE;

    @Option(name = "--save-resp", description = "whether to save the request")
    private Boolean saveResp = Boolean.FALSE;

    @Option(name = "--unknown-as", description = "expected status for unknown certificate")
    @Completion(QaCompleters.CertStatusCompleter.class)
    private String unknownAs;

    @Option(name = "--no-sig-verify", description = "where to verify the signature")
    private Boolean noSigVerify = Boolean.FALSE;

    @Option(name = "--exp-sig-alg", description = "expected signature algorithm")
    @Completion(Completers.SigAlgCompleter.class)
    private String sigAlgo;

    @Option(name = "--exp-nextupdate", description = "occurrence of nextUpdate")
    @Completion(QaCompleters.OccurrenceCompleter.class)
    private String nextUpdateOccurrenceText = TripleState.optional.name();

    @Option(name = "--exp-nonce", description = "occurrence of nonce")
    @Completion(QaCompleters.OccurrenceCompleter.class)
    private String nonceOccurrenceText = TripleState.optional.name();

    @Reference
    private SecurityFactory securityFactory;

    @Reference
    private OcspRequestor requestor;

    private TripleState expectedNextUpdateOccurrence;

    private TripleState expectedNonceOccurrence;

    @Override
    protected final Object execute0() throws Exception {
      expectedNextUpdateOccurrence = TripleState.valueOf(nextUpdateOccurrenceText);
      expectedNonceOccurrence = TripleState.valueOf(nonceOccurrenceText);

      File outDir = new File(outDirStr);
      File messageDir = new File(outDir, "messages");
      IoUtil.mkdirs(messageDir);

      File detailsDir = new File(outDir, "details");
      IoUtil.mkdirs(detailsDir);

      println("The result is saved in the folder " + outDir.getPath());

      String linuxIssuer = (respIssuerFile != null) ? "-CAfile ../../responder_issuer.pem" : "-no_cert_verify";

      String winIssuer = (respIssuerFile != null) ? "-CAfile ..\\..\\responder_issuer.pem" : "-no_cert_verify";

      String linuxMsg = "openssl ocsp -text ";
      String winMsg = "openssl ocsp -text ";

      String shellFilePath = null;

      if (saveReq && saveResp) {
        linuxMsg += linuxIssuer + " -reqin request.der -respin response.der";
        winMsg += winIssuer + " -reqin request.der -respin response.der";
        shellFilePath = new File(outDir, "verify-req-resp").getPath();
      } else if (saveReq) {
        linuxMsg += "-reqin request.der\n";
        winMsg += "-reqin request.der\n";
        shellFilePath = new File(outDir, "verify-req").getPath();
      } else if (saveResp) {
        linuxMsg += linuxIssuer + " -respin response.der\n";
        winMsg += winIssuer + " -respin response.der\n";
        shellFilePath = new File(outDir, "verify-resp").getPath();
      }

      if (shellFilePath != null) {
        File linuxShellFile = new File(shellFilePath + ".sh");
        IoUtil.save(linuxShellFile, StringUtil.toUtf8Bytes("#!/bin/sh\n" + linuxMsg));
        IoUtil.save(shellFilePath + ".bat", StringUtil.toUtf8Bytes("@echo off\r\n" + winMsg));
        linuxShellFile.setExecutable(true);
      }

      X509Cert issuerCert = X509Util.parseCert(new File(issuerCertFile));

      X509Cert respIssuer = null;
      if (respIssuerFile != null) {
        respIssuer = X509Util.parseCert(new File(respIssuerFile));
        IoUtil.save(new File(outDir, "responder-issuer.pem"),
            StringUtil.toUtf8Bytes(X509Util.toPemCert(respIssuer)));
      }

      RequestOptions requestOptions = getRequestOptions();

      IssuerHash issuerHash = new IssuerHash(requestOptions.getHashAlgorithm(), issuerCert);

      int numSucc = 0;
      int numFail = 0;

      try (OutputStream resultOut = Files.newOutputStream(Paths.get(outDir.getPath(), "overview.txt"));
           BufferedReader snReader = Files.newBufferedReader(Paths.get(snFile))) {
        URL serverUrl = new URL(serverUrlStr);

        OcspQa ocspQa = new OcspQa(securityFactory);

        // Content of a line:
        // <hex-encoded serial number>[,<reason code>,<revocation time in epoch seconds>]
        int lineNo = 0;
        String line;

        int sum = 0;
        Instant startDate = Instant.now();
        Instant lastPrintDate = Instant.ofEpochMilli(0);
        while ((line = snReader.readLine()) != null) {
          lineNo++;
          line = line.trim();

          if (line.startsWith("#") || line.isEmpty()) {
            resultOut.write(StringUtil.toUtf8Bytes(line));
            resultOut.write('\n');
            continue;
          }

          sum++;
          String resultText = lineNo + ": " + line + ": ";
          try {
            ValidationResult result = processOcspQuery(ocspQa, line, messageDir, detailsDir,
                serverUrl, respIssuer, issuerCert, issuerHash, requestOptions);
            if (result.isAllSuccessful()) {
              numSucc++;
              resultText += "valid";
            } else {
              numFail++;
              resultText += "invalid";
            }
          } catch (Throwable th) {
            LogUtil.error(LOG, th);
            numFail++;
            resultText += "error - " + th.getMessage();
          }

          println(resultText, resultOut);

          Instant now = Instant.now();
          if (Duration.between(lastPrintDate, now).toMillis() > 980) { // use 980 ms to ensure the output every second.
            String duration = StringUtil.formatTime(Duration.between(startDate, now).getSeconds(), false);
            print("\rProcessed " + sum + " requests in " + duration);
            lastPrintDate = now;
          }
        }

        // unknown serial number
        lineNo++;
        byte[] bytes = RandomUtil.nextBytes(16);
        bytes[0] = (byte) (0x7F & bytes[0]);
        BigInteger serialNumber = new BigInteger(bytes);

        String resultText = lineNo + ": " + serialNumber.toString(16) + ",unknown: ";
        try {
          ValidationResult result = processOcspQuery(ocspQa, serialNumber, OcspCertStatus.unknown,
              null, messageDir, detailsDir, serverUrl, respIssuer, issuerCert, issuerHash, requestOptions);
          if (result.isAllSuccessful()) {
            numSucc++;
            resultText += "valid";
          } else {
            numFail++;
            resultText += "invalid";
          }
        } catch (Throwable th) {
          LogUtil.error(LOG, th);
          numFail++;
          resultText += "error - " + th.getMessage();
        }

        sum++;

        print("\rProcessed " + sum + " requests in "
            + StringUtil.formatTime(Duration.between(startDate, Instant.now()).getSeconds(), false));
        println("");

        println(resultText, resultOut);

        String message = StringUtil.concatObjectsCap(200, "=====BEGIN SUMMARY=====",
            "\n       url: ", serverUrlStr, "\n       sum: ", numFail + numSucc,
            "\nsuccessful: ", numSucc, "\n    failed: ", numFail, "\n=====END SUMMARY=====");
        println(message);
        println(message, resultOut);
      }

      return null;
    } // method execute0

    private ValidationResult processOcspQuery(
        OcspQa ocspQa, String line, File messageDir, File detailsDir, URL serverUrl, X509Cert respIssuer,
        X509Cert issuerCert, IssuerHash issuerHash, RequestOptions requestOptions)
        throws Exception {
      StringTokenizer tokens = new StringTokenizer(line, ",;:");

      int count = tokens.countTokens();
      BigInteger serialNumber;
      OcspCertStatus status;
      Instant revTime = null;
      try {
        serialNumber = toBigInt(tokens.nextToken(), hex);

        if (count > 1) {
          String token = tokens.nextToken();
          if ("unknown".equalsIgnoreCase(token)) {
            status = OcspCertStatus.unknown;
          } else if ("good".equalsIgnoreCase(token)) {
            status = OcspCertStatus.good;
          } else {
            CrlReason reason = CrlReason.forNameOrText(token);
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
                throw new Exception("invalid reason " + reason);
            }
          }
        } else {
          status = OcspCertStatus.good;
        }

        if (count > 2 && status != OcspCertStatus.good && status != OcspCertStatus.unknown) {
          revTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(tokens.nextToken());
        }
      } catch (Exception ex) {
        LogUtil.warn(LOG, ex, "Could not parse line '" + line + "'");
        throw new IllegalArgumentException("illegal line");
      }

      return processOcspQuery(ocspQa, serialNumber, status, revTime, messageDir, detailsDir,
          serverUrl, respIssuer, issuerCert, issuerHash, requestOptions);
    } // method processOcspQuery

    private ValidationResult processOcspQuery(
        OcspQa ocspQa, BigInteger serialNumber, OcspCertStatus status, Instant revTime,
        File messageDir, File detailsDir, URL serverUrl, X509Cert respIssuer,
        X509Cert issuerCert, IssuerHash issuerHash, RequestOptions requestOptions)
        throws Exception {
      if (status == OcspCertStatus.unknown) {
        if (isNotBlank(unknownAs)) {
          status = OcspCertStatus.forName(unknownAs);
        }
      }

      ReqRespDebug debug = null;
      if (saveReq || saveResp) {
        debug = new ReqRespDebug(saveReq, saveResp);
      }

      OCSPResp response;
      try {
        response = requestor.ask(issuerCert, serialNumber, serverUrl, requestOptions, debug);
      } finally {
        if (debug != null && debug.size() > 0) {
          ReqRespPair reqResp = debug.get(0);
          String filename = serialNumber.toString(16);

          if (saveReq) {
            byte[] bytes = reqResp.getRequest();
            if (bytes != null) {
              IoUtil.save(new File(messageDir, filename + FILE_SEP + "request.der"), bytes);
            }
          }

          if (saveResp) {
            byte[] bytes = reqResp.getResponse();
            if (bytes != null) {
              IoUtil.save(new File(messageDir, filename + FILE_SEP + "response.der"), bytes);
            }
          }
        } // end if
      } // end finally

      // analyze the result
      OcspResponseOption responseOption = new OcspResponseOption();
      responseOption.setNextUpdateOccurrence(expectedNextUpdateOccurrence);
      responseOption.setNonceOccurrence(expectedNonceOccurrence);
      responseOption.setRespIssuer(respIssuer);
      if(isNotBlank(sigAlgo)) {
        responseOption.setSignatureAlg(SignAlgo.getInstance(sigAlgo));
      }

      ValidationResult ret = ocspQa.checkOcsp(response, issuerHash, serialNumber, null,
          status, responseOption, revTime, noSigVerify);

      String validity = ret.isAllSuccessful() ? "valid" : "invalid";
      String hexSerial = serialNumber.toString(16);
      StringBuilder sb = new StringBuilder("OCSP response for ");
      sb.append(serialNumber).append(" (0x").append(hexSerial).append(") is ").append(validity);

      for (ValidationIssue issue : ret.getValidationIssues()) {
        sb.append("\n");
        OcspQaStatusAction.format(issue, "    ", sb);
      }

      IoUtil.save(new File(detailsDir, hexSerial + "." + validity), StringUtil.toUtf8Bytes(sb.toString()));
      return ret;
    } // method processOcspQuery

    private void println(String message, OutputStream out) throws IOException {
      out.write(StringUtil.toUtf8Bytes(message));
      out.write('\n');
    } // method println

  } // class BatchOcspQaStatusAction

  @Command(scope = "xiqa", name = "benchmark-ocsp-status", description = "OCSP benchmark")
  @Service
  public static class BenchmarkOcspStatusAction extends CommonOcspStatusAction {
    @Option(name = "--hex", description = "serial number without prefix is hex number")
    private Boolean hex = Boolean.FALSE;

    @Option(name = "--serial", aliases = "-s",
        description = "comma-separated serial numbers or ranges (like 1,3,6-10)\n"
            + "(exactly one of serial, serial-file and cert must be specified)")
    private String serialNumberList;

    @Option(name = "--serial-file", description = "file that contains serial numbers")
    @Completion(FileCompleter.class)
    private String serialNumberFile;

    @Option(name = "--cert", multiValued = true, description = "certificate files")
    @Completion(FileCompleter.class)
    private List<String> certFiles;

    @Option(name = "--duration", description = "duration")
    private String duration = "30s";

    @Option(name = "--thread", description = "number of threads")
    private Integer numThreads = 5;

    @Option(name = "--url", required = true, description = "OCSP responder URL")
    private String serverUrl;

    @Option(name = "--max-num", description = "maximal number of OCSP queries\n0 for unlimited")
    private Integer maxRequests = 0;

    @Override
    protected Object execute0() throws Exception {
      int ii = 0;
      if (serialNumberList != null) {
        ii++;
      }

      if (serialNumberFile != null) {
        ii++;
      }

      if (CollectionUtil.isNotEmpty(certFiles)) {
        ii++;
      }

      if (ii != 1) {
        throw new IllegalCmdParamException("exactly one of serial, serial-file and cert must be specified");
      }

      if (numThreads < 1) {
        throw new IllegalCmdParamException("invalid number of threads " + numThreads);
      }

      Iterator<BigInteger> serialNumberIterator;

      if (serialNumberFile != null) {
        serialNumberIterator = new FileBigIntegerIterator(IoUtil.expandFilepath(serialNumberFile), hex, true);
      } else {
        List<BigIntegerRange> serialNumbers = new LinkedList<>();
        if (serialNumberList != null) {
          StringTokenizer st = new StringTokenizer(serialNumberList, ", ");
          while (st.hasMoreTokens()) {
            String token = st.nextToken();
            StringTokenizer st2 = new StringTokenizer(token, "-");
            BigInteger from = toBigInt(st2.nextToken(), hex);
            BigInteger to = st2.hasMoreTokens() ? toBigInt(st2.nextToken(), hex) : from;
            serialNumbers.add(new BigIntegerRange(from, to));
          }
        } else {
          for (String certFile : certFiles) {
            X509Cert cert;
            try {
              cert = X509Util.parseCert(new File(certFile));
            } catch (Exception ex) {
              throw new IllegalCmdParamException("invalid certificate file  '" + certFile + "'", ex);
            }
            BigInteger serial = cert.getSerialNumber();
            serialNumbers.add(new BigIntegerRange(serial, serial));
          }
        }

        serialNumberIterator = new RangeBigIntegerIterator(serialNumbers, true);
      }

      try {
        String description = StringUtil.concatObjects("issuer cert: ", issuerCertFile,
            "\nserver URL: ",serverUrl, "\nmaxRequest: ", maxRequests, "\nhash: ", hashAlgo);

        X509Cert issuerCert = X509Util.parseCert(new File(issuerCertFile));

        RequestOptions options = getRequestOptions();
        OcspBenchmark loadTest = new OcspBenchmark(issuerCert, serverUrl, options,
            serialNumberIterator, maxRequests, description);
        loadTest.setDuration(duration).setThreads(numThreads).execute();
      } finally {
        if (serialNumberIterator instanceof FileBigIntegerIterator) {
          ((FileBigIntegerIterator) serialNumberIterator).close();
        }
      }

      return null;
    } // end execute0

  } // class BenchmarkOcspStatusAction

  @Command(scope = "xiqa", name = "qa-ocsp-status", description = "request certificate status (QA)")
  @Service
  public static class OcspQaStatusAction extends BaseOcspStatusAction {

    @Option(name = "--exp-error", description = "expected error")
    @Completion(QaCompleters.OcspErrorCompleter.class)
    private String errorText;

    @Option(name = "--exp-status", multiValued = true, description = "expected status")
    @Completion(QaCompleters.CertStatusCompleter.class)
    private List<String> statusTexts;

    @Option(name = "--rev-time", multiValued = true, description = "revocation time, UTC time of format yyyyMMddHHmmss")
    private List<String> revTimeTexts;

    @Option(name = "--exp-sig-alg", description = "expected signature algorithm")
    @Completion(Completers.SigAlgCompleter.class)
    private String sigAlgo;

    @Option(name = "--no-sig-verify", description = "no verification of the signature")
    private Boolean noSigVerify = Boolean.FALSE;

    @Option(name = "--exp-nextupdate", description = "occurrence of nextUpdate")
    @Completion(QaCompleters.OccurrenceCompleter.class)
    private String nextUpdateOccurrenceText = TripleState.optional.name();

    @Option(name = "--exp-nonce", description = "occurrence of nonce")
    @Completion(QaCompleters.OccurrenceCompleter.class)
    private String nonceOccurrenceText = TripleState.optional.name();

    @Reference
    private SecurityFactory securityFactory;

    private OcspQa ocspQa;

    private OcspError expectedOcspError;

    private Map<BigInteger, OcspCertStatus> expectedStatuses;

    private Map<BigInteger, Instant> expectedRevTimes;

    private TripleState expectedNextUpdateOccurrence;

    private TripleState expectedNonceOccurrence;

    @Override
    protected void checkParameters(
        X509Cert respIssuer, List<BigInteger> serialNumbers, Map<BigInteger, byte[]> encodedCerts)
        throws Exception {
      Args.notEmpty(serialNumbers, "serialNunmbers");

      if (isBlank(errorText) && isEmpty(statusTexts)) {
        throw new IllegalArgumentException("neither expError nor expStatus is set, this is not permitted");
      }

      if (isNotBlank(errorText) && isNotEmpty(statusTexts)) {
        throw new IllegalArgumentException("both expError and expStatus are set, this is not permitted");
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

        expectedRevTimes = new HashMap<>();
        final int n = serialNumbers.size();

        for (int i = 0; i < n; i++) {
          Instant revTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(revTimeTexts.get(i));
          expectedRevTimes.put(serialNumbers.get(i), revTime);
        }
      }

      expectedNextUpdateOccurrence = TripleState.valueOf(nextUpdateOccurrenceText);
      expectedNonceOccurrence = TripleState.valueOf(nonceOccurrenceText);
    } // method checkParameters

    @Override
    protected void processResponse(
        OCSPResp response, X509Cert respIssuer, IssuerHash issuerHash,
        List<BigInteger> serialNumbers, Map<BigInteger, byte[]> encodedCerts)
        throws Exception {
      OcspResponseOption responseOption = new OcspResponseOption();
      responseOption.setNextUpdateOccurrence(expectedNextUpdateOccurrence);
      responseOption.setNonceOccurrence(expectedNonceOccurrence);
      responseOption.setRespIssuer(respIssuer);
      if (isNotBlank(sigAlgo)) {
        responseOption.setSignatureAlg(SignAlgo.getInstance(sigAlgo));
      }

      if (ocspQa == null) {
        ocspQa = new OcspQa(securityFactory);
      }

      ValidationResult result;
      if (expectedOcspError != null) {
        result = ocspQa.checkOcsp(response, expectedOcspError);
      } else {
        result = ocspQa.checkOcsp(response, issuerHash, serialNumbers, encodedCerts,
                    expectedStatuses, expectedRevTimes, responseOption, noSigVerify);
      }

      StringBuilder sb = new StringBuilder(50);
      sb.append("OCSP response is ").append(result.isAllSuccessful() ? "valid" : "invalid");

      if (verbose) {
        for (ValidationIssue issue : result.getValidationIssues()) {
          sb.append("\n");
          format(issue, "    ", sb);
        }
      } else {
        for (ValidationIssue issue : result.getValidationIssues()) {
          if (issue.isFailed()) {
            sb.append("\n");
            format(issue, "    ", sb);
          }
        }
      }

      println(sb.toString());
      if (!result.isAllSuccessful()) {
        throw new CmdFailure("OCSP response is invalid");
      }
    } // method processResponse

    static void format(ValidationIssue issue, String prefix, StringBuilder sb) {
      sb.append(prefix).append(issue.getCode()).append(", ").append(issue.getDescription());
      sb.append(", ").append(issue.isFailed() ? "failed" : "successful");
      if (issue.getFailureMessage() != null) {
        sb.append(", ").append(issue.getFailureMessage());
      }
    } // method format

  } // class OcspQaStatusAction

}
