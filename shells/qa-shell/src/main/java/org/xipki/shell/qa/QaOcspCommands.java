// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.qa;

import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.client.RequestOptions;
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
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.pkix.CrlReason;
import org.xipki.security.pkix.IssuerHash;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.completer.DirPathCompleter;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.pki.client.PkiClientRuntime;
import org.xipki.shell.xi.Completers;
import org.xipki.util.codec.TripleState;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.misc.RandomUtil;
import org.xipki.util.extra.misc.ReqRespDebug;
import org.xipki.util.extra.misc.ReqRespDebug.ReqRespPair;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * The QA shell.
 *
 * @author Lijun Liao (xipki)
 */

class QaOcspCommands {

  @Command(name = "batch-ocsp-status",
      description = "batch request status of certificates (QA)", mixinStandardHelpOptions = true)
  static class BatchOcspStatusCommand extends ShellBaseCommand {

    private static final Logger LOG = LoggerFactory.getLogger(BatchOcspStatusCommand.class);

    @Option(names = {"--issuer", "-i"}, required = true, description = "issuer certificate file")
    @Completion(FilePathCompleter.class)
    private String issuerCertFile;

    @Option(names = "--resp-issuer", description = "certificate file of the responder's issuer")
    @Completion(FilePathCompleter.class)
    private String respIssuerFile;

    @Option(names = "--url", required = true, description = "OCSP responder URL")
    private String serverUrlStr;

    @Option(names = "--sn-file", required = true, description =
        "file containing serial-number[,status[,revocation-time]] lines")
    @Completion(FilePathCompleter.class)
    private String snFile;

    @Option(names = "--hex", description = "serial number without prefix is hex number")
    private Boolean hex = Boolean.FALSE;

    @Option(names = "--out-dir", required = true, description =
        "folder to save the request and response")
    @Completion(DirPathCompleter.class)
    private String outDirStr;

    @Option(names = "--save-req", description = "whether to save the request")
    private Boolean saveReq = Boolean.FALSE;

    @Option(names = "--save-resp", description = "whether to save the response")
    private Boolean saveResp = Boolean.FALSE;

    @Option(names = "--unknown-as", description = "expected status for unknown certificate")
    private String unknownAs;

    @Option(names = "--no-sig-verify", description = "whether to verify the signature")
    private Boolean noSigVerify = Boolean.FALSE;

    @Option(names = "--exp-sig-alg", description = "expected signature algorithm")
    @Completion(Completers.SigAlgoCompleter.class)
    private String sigAlgo;

    // TODO: change to TripleStateCompleter, check if no explicit completion, whether TAB works
    @Option(names = "--exp-nextupdate", description = "occurrence of nextUpdate")
    @Completion(Completers.TripleStateCompleter.class)
    private String nextUpdateOccurrenceText = TripleState.optional.name();

    @Option(names = "--exp-certhash", description = "occurrence of certHash")
    @Completion(Completers.TripleStateCompleter.class)
    private String certhashOccurrenceText = TripleState.optional.name();

    @Option(names = "--exp-certhash-alg", description = "certHash algorithm")
    @Completion(Completers.HashAlgoCompleter.class)
    private String certhashAlg;

    @Option(names = "--exp-nonce", description = "occurrence of nonce")
    @Completion(Completers.TripleStateCompleter.class)
    private String nonceOccurrenceText = TripleState.optional.name();

    @Override
    public void run() {
      try {
        TripleState expectedCerthashOccurrence = TripleState.valueOf(certhashOccurrenceText);
        TripleState expectedNextUpdateOccurrence = TripleState.valueOf(nextUpdateOccurrenceText);
        TripleState expectedNonceOccurrence = TripleState.valueOf(nonceOccurrenceText);

        File outDir = new File(outDirStr);
        File messageDir = new File(outDir, "messages");
        IoUtil.mkdirs(messageDir);
        File detailsDir = new File(outDir, "details");
        IoUtil.mkdirs(detailsDir);

        println("The result is saved in the folder " + outDir.getPath());

        String linuxIssuer = (respIssuerFile != null)
            ? "-CAfile ../../responder_issuer.pem" : "-no_cert_verify";
        String winIssuer = (respIssuerFile != null)
            ? "-CAfile ..\\..\\responder_issuer.pem" : "-no_cert_verify";
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

        RequestOptions requestOptions = new RequestOptions();
        requestOptions.setHashAlgorithm(HashAlgo.SHA256);
        IssuerHash issuerHash = new IssuerHash(requestOptions.hashAlgorithm(), issuerCert);
        OcspQa ocspQa = new OcspQa(PkiClientRuntime.getSecurities().securityFactory());

        int numSucc = 0;
        int numFail = 0;
        try (OutputStream resultOut = Files.newOutputStream(Paths.get(outDir.getPath(),
                                      "overview.txt"));
             BufferedReader snReader = Files.newBufferedReader(Paths.get(snFile))) {
          URL serverUrl = new URL(serverUrlStr);
          int lineNo = 0;
          int sum = 0;
          Instant startDate = Instant.now();
          Instant lastPrintDate = Instant.ofEpochMilli(0);
          String line;
          while ((line = snReader.readLine()) != null) {
            lineNo++;
            line = line.trim();
            if (line.startsWith("#") || line.isEmpty()) {
              println(line, resultOut);
              continue;
            }

            sum++;
            String resultText = lineNo + ": " + line + ": ";
            try {
              ValidationResult result = processOcspLine(ocspQa, line, messageDir, detailsDir,
                  serverUrl, respIssuer, issuerCert, issuerHash, requestOptions,
                  expectedCerthashOccurrence, expectedNextUpdateOccurrence,
                  expectedNonceOccurrence);
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
            if (Duration.between(lastPrintDate, now).toMillis() > 980) {
              String duration = StringUtil.formatTime(
                  Duration.between(startDate, now).getSeconds(), false);
              out().print("\rProcessed " + sum + " requests in " + duration);
              out().flush();
              lastPrintDate = now;
            }
          }

          lineNo++;
          byte[] bytes = RandomUtil.nextBytes(16);
          bytes[0] = (byte) (0x7F & bytes[0]);
          BigInteger serialNumber = new BigInteger(bytes);
          String resultText = lineNo + ": " + serialNumber.toString(16) + ",unknown: ";
          try {
            ValidationResult result = processOcspQuery(ocspQa, serialNumber, OcspCertStatus.unknown,
                null, messageDir, detailsDir, serverUrl, respIssuer, issuerCert, issuerHash,
                requestOptions, expectedCerthashOccurrence, expectedNextUpdateOccurrence,
                expectedNonceOccurrence);
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
          out().print("\rProcessed " + sum + " requests in " + StringUtil.formatTime(
              Duration.between(startDate, Instant.now()).getSeconds(), false));
          out().flush();
          println("");
          println(resultText, resultOut);

          String message = StringUtil.concatObjectsCap(200,
              "=====BEGIN SUMMARY=====",
              "\n       url: ", serverUrlStr,
              "\n       sum: ", numFail + numSucc,
              "\nsuccessful: ", numSucc,
              "\n    failed: ", numFail,
              "\n=====END SUMMARY=====");
          println(message);
          println(message, resultOut);
        }
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not batch validate OCSP status: "
                + ex.getMessage(), ex);
      }
    }

    private ValidationResult processOcspLine(OcspQa ocspQa, String line, File messageDir,
        File detailsDir, URL serverUrl, X509Cert respIssuer, X509Cert issuerCert,
        IssuerHash issuerHash, RequestOptions requestOptions,
        TripleState expectedCerthashOccurrence, TripleState expectedNextUpdateOccurrence,
        TripleState expectedNonceOccurrence) throws Exception {
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
          serverUrl, respIssuer, issuerCert, issuerHash, requestOptions,
          expectedCerthashOccurrence, expectedNextUpdateOccurrence, expectedNonceOccurrence);
    }

    private ValidationResult processOcspQuery(OcspQa ocspQa, BigInteger serialNumber,
        OcspCertStatus status, Instant revTime, File messageDir, File detailsDir, URL serverUrl,
        X509Cert respIssuer, X509Cert issuerCert, IssuerHash issuerHash,
        RequestOptions requestOptions, TripleState expectedCerthashOccurrence,
        TripleState expectedNextUpdateOccurrence, TripleState expectedNonceOccurrence)
        throws Exception {
      if (status == OcspCertStatus.unknown && StringUtil.isNotBlank(unknownAs)) {
        status = OcspCertStatus.forName(unknownAs);
      }

      ReqRespDebug debug = null;
      if (saveReq || saveResp) {
        debug = new ReqRespDebug(saveReq, saveResp);
      }

      OCSPResp response;
      try {
        response = PkiClientRuntime.getOcspRequestor().ask(
            issuerCert, serialNumber, serverUrl, requestOptions, debug);
      } finally {
        if (debug != null && debug.size() > 0) {
          ReqRespPair reqResp = debug.get(0);
          String filename = serialNumber.toString(16);
          File serialDir = new File(messageDir, filename);
          IoUtil.mkdirs(serialDir);
          if (saveReq && reqResp.request() != null) {
            IoUtil.save(new File(serialDir, "request.der"), reqResp.request());
          }
          if (saveResp && reqResp.response() != null) {
            IoUtil.save(new File(serialDir, "response.der"), reqResp.response());
          }
        }
      }

      OcspResponseOption responseOption = new OcspResponseOption();
      responseOption.setNextUpdateOccurrence(expectedNextUpdateOccurrence);
      responseOption.setCerthashOccurrence(expectedCerthashOccurrence);
      responseOption.setNonceOccurrence(expectedNonceOccurrence);
      responseOption.setRespIssuer(respIssuer);
      if (StringUtil.isNotBlank(sigAlgo)) {
        responseOption.setSignatureAlg(SignAlgo.getInstance(sigAlgo));
      }
      if (StringUtil.isNotBlank(certhashAlg)) {
        responseOption.setCerthashAlg(HashAlgo.getInstance(certhashAlg));
      }

      ValidationResult ret = ocspQa.checkOcsp(response, issuerHash, serialNumber, null,
          status, responseOption, revTime, noSigVerify);
      String validity = ret.isAllSuccessful() ? "valid" : "invalid";
      String hexSerial = serialNumber.toString(16);
      StringBuilder sb = new StringBuilder("OCSP response for ")
          .append(serialNumber).append(" (0x").append(hexSerial).append(") is ")
          .append(validity);
      for (ValidationIssue issue : ret.getValidationIssues()) {
        sb.append('\n');
        formatValidationIssue(issue, "    ", sb);
      }
      IoUtil.save(new File(detailsDir, hexSerial + "." + validity),
          StringUtil.toUtf8Bytes(sb.toString()));
      return ret;
    }

    private void println(String message, OutputStream out) throws IOException {
      out.write(StringUtil.toUtf8Bytes(message));
      out.write('\n');
    }
  }

  @Command(name = "qa-ocsp-status", description = "request certificate status (QA)",
      mixinStandardHelpOptions = true)
  static class QaOcspStatusCommand extends ShellBaseCommand {
    @Option(names = {"--issuer", "-i"}, required = true, description = "issuer certificate file")
    @Completion(FilePathCompleter.class)
    private String issuerCertFile;

    @Option(names = "--resp-issuer", description = "responder issuer certificate file")
    @Completion(FilePathCompleter.class)
    private String respIssuerFile;

    @Option(names = "--url", required = true, description = "OCSP responder URL")
    private String serverUrl;

    @Option(names = "--serial", split = ",", description = "serial numbers")
    private List<String> serialNumbersS;

    @Option(names = "--cert", split = ",", description = "certificate files")
    @Completion(FilePathCompleter.class)
    private List<String> certFiles;

    @Option(names = "--nonce", description = "use nonce")
    private Boolean useNonce = Boolean.FALSE;

    @Option(names = "--nonce-len", description = "nonce length in octets")
    private Integer nonceLen;

    @Option(names = "--allow-no-nonce-in-resp", description = "allow response without nonce")
    private Boolean allowNoNonceInResponse = Boolean.FALSE;

    @Option(names = "--hash", description = "hash algorithm name")
    @Completion(Completers.HashAlgoCompleter.class)
    private String hashAlgo = "SHA256";

    @Option(names = "--sig-alg", split = ",", description = "preferred signature algorithms")
    @Completion(Completers.SigAlgoCompleter.class)
    private List<String> prefSigAlgs;

    @Option(names = "--http-get", description = "use HTTP GET for small request")
    private Boolean useHttpGetForSmallRequest = Boolean.FALSE;

    @Option(names = "--sign", description = "sign request")
    private Boolean signRequest = Boolean.FALSE;

    @Option(names = "--exp-error", description = "expected error")
    private String errorText;

    @Option(names = "--exp-status", split = ",", description = "expected status")
    @Completion(Completers.StatusCompleter.class)
    private List<String> statusTexts;

    @Option(names = "--rev-time", split = ",", description = "revocation time UTC yyyyMMddHHmmss")
    private List<String> revTimeTexts;

    @Option(names = "--exp-sig-alg", description = "expected signature algorithm")
    @Completion(Completers.SigAlgoCompleter.class)
    private String sigAlgo;

    @Option(names = "--no-sig-verify", description = "no verification of the signature")
    private Boolean noSigVerify = Boolean.FALSE;

    @Option(names = "--exp-nextupdate", description = "occurrence of nextUpdate")
    private String nextUpdateOccurrenceText = TripleState.optional.name();

    @Option(names = "--exp-certhash", description = "occurrence of certHash")
    @Completion(Completers.TripleStateCompleter.class)
    private String certhashOccurrenceText = TripleState.optional.name();

    @Option(names = "--exp-certhash-alg", description = "certHash algorithm")
    @Completion(Completers.HashAlgoCompleter.class)
    private String certhashAlg;

    @Option(names = "--exp-nonce", description = "occurrence of nonce")
    @Completion(Completers.TripleStateCompleter.class)
    private String nonceOccurrenceText = TripleState.optional.name();

    @Option(names = "--hex", description = "serial number without prefix is hex number")
    private Boolean hex = Boolean.FALSE;

    @Option(names = {"--verbose", "-v"}, description = "show status verbosely")
    private boolean verbose;

    @Override
    public void run() {
      try {
        X509Cert issuerCert = X509Util.parseCert(new File(issuerCertFile));
        X509Cert respIssuer = StringUtil.isBlank(respIssuerFile)
            ? null : X509Util.parseCert(new File(respIssuerFile));
        List<BigInteger> serialNumbers = new ArrayList<>();
        Map<BigInteger, byte[]> encodedCerts = new HashMap<>();

        if (CollectionUtil.isNotEmpty(certFiles)) {
          for (String certFile : certFiles) {
            X509Cert cert = X509Util.parseCert(new File(certFile));
            serialNumbers.add(cert.serialNumber());
            encodedCerts.put(cert.serialNumber(), cert.getEncoded());
          }
        }

        if (CollectionUtil.isNotEmpty(serialNumbersS)) {
          for (String token : serialNumbersS) {
            serialNumbers.add(toBigInt(token, hex));
          }
        }

        if (serialNumbers.isEmpty()) {
          throw new IllegalArgumentException("no serial numbers are specified");
        }
        if (StringUtil.isBlank(errorText) && CollectionUtil.isEmpty(statusTexts)) {
          throw new IllegalArgumentException("neither expError nor expStatus is set");
        }
        if (StringUtil.isNotBlank(errorText) && CollectionUtil.isNotEmpty(statusTexts)) {
          throw new IllegalArgumentException("both expError and expStatus are set");
        }

        RequestOptions options = new RequestOptions();
        options.setUseNonce(useNonce);
        if (nonceLen != null) {
          options.setNonceLen(nonceLen);
        }
        options.setAllowNoNonceInResponse(allowNoNonceInResponse);
        options.setHashAlgorithm(HashAlgo.getInstance(hashAlgo));
        options.setSignRequest(signRequest);
        options.setUseHttpGetForRequest(useHttpGetForSmallRequest);
        if (CollectionUtil.isNotEmpty(prefSigAlgs)) {
          SignAlgo[] algos = new SignAlgo[prefSigAlgs.size()];
          for (int i = 0; i < algos.length; i++) {
            algos[i] = SignAlgo.getInstance(prefSigAlgs.get(i));
          }
          options.setPreferredSignatureAlgorithms(algos);
        }

        OCSPResp response = PkiClientRuntime.getOcspRequestor().ask(
            issuerCert, serialNumbers.toArray(new BigInteger[0]), new URL(serverUrl),
            options, null);

        OcspQa ocspQa = new OcspQa(PkiClientRuntime.getSecurities().securityFactory());
        ValidationResult result;
        if (StringUtil.isNotBlank(errorText)) {
          result = ocspQa.checkOcsp(response, OcspError.forName(errorText));
        } else {
          if (statusTexts.size() != serialNumbers.size()) {
            throw new IllegalArgumentException("number of expStatus is invalid: "
                + statusTexts.size() + ", it should be " + serialNumbers.size());
          }

          Map<BigInteger, OcspCertStatus> expectedStatuses = new HashMap<>();
          for (int i = 0; i < serialNumbers.size(); i++) {
            expectedStatuses.put(serialNumbers.get(i), OcspCertStatus.forName(statusTexts.get(i)));
          }

          Map<BigInteger, Instant> expectedRevTimes = null;
          if (CollectionUtil.isNotEmpty(revTimeTexts)) {
            if (revTimeTexts.size() != serialNumbers.size()) {
              throw new IllegalArgumentException("number of revTimes is invalid: "
                  + revTimeTexts.size() + ", it should be " + serialNumbers.size());
            }
            expectedRevTimes = new HashMap<>();
            for (int i = 0; i < serialNumbers.size(); i++) {
              expectedRevTimes.put(serialNumbers.get(i),
                  DateUtil.parseUtcTimeyyyyMMddhhmmss(revTimeTexts.get(i)));
            }
          }

          OcspResponseOption responseOption = new OcspResponseOption();
          responseOption.setNextUpdateOccurrence(TripleState.valueOf(nextUpdateOccurrenceText));
          responseOption.setCerthashOccurrence(TripleState.valueOf(certhashOccurrenceText));
          responseOption.setNonceOccurrence(TripleState.valueOf(nonceOccurrenceText));
          responseOption.setRespIssuer(respIssuer);
          if (StringUtil.isNotBlank(sigAlgo)) {
            responseOption.setSignatureAlg(SignAlgo.getInstance(sigAlgo));
          }
          if (StringUtil.isNotBlank(certhashAlg)) {
            responseOption.setCerthashAlg(HashAlgo.getInstance(certhashAlg));
          }

          IssuerHash issuerHash = new IssuerHash(options.hashAlgorithm(), issuerCert);
          result = ocspQa.checkOcsp(response, issuerHash, serialNumbers,
              encodedCerts.isEmpty() ? null : encodedCerts, expectedStatuses,
              expectedRevTimes, responseOption, noSigVerify);
        }

        StringBuilder sb = new StringBuilder(64);
        sb.append("OCSP response is ").append(result.isAllSuccessful() ? "valid" : "invalid");
        for (ValidationIssue issue : result.getValidationIssues()) {
          if (verbose || issue.isFailed()) {
            sb.append("\n");
            formatValidationIssue(issue, "    ", sb);
          }
        }
        println(sb.toString());
        if (!result.isAllSuccessful()) {
          throw new RuntimeException("OCSP response is invalid");
        }
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not validate OCSP response: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "benchmark-ocsp-status", description = "OCSP benchmark",
      mixinStandardHelpOptions = true)
  static class BenchmarkOcspStatusCommand extends ShellBaseCommand {
    @Option(names = {"--issuer", "-i"}, required = true, description = "issuer certificate file")
    @Completion(FilePathCompleter.class)
    private String issuerCertFile;

    @Option(names = "--hex", description = "serial number without prefix is hex number")
    private Boolean hex = Boolean.FALSE;

    @Option(names = {"--serial", "-s"}, description = "comma-separated serial numbers or ranges")
    private String serialNumberList;

    @Option(names = "--serial-file", description = "file that contains serial numbers")
    @Completion(FilePathCompleter.class)
    private String serialNumberFile;

    @Option(names = {"--cert", "-c"}, split = ",", description = "certificate files")
    @Completion(FilePathCompleter.class)
    private List<String> certFiles;

    @Option(names = "--duration", description = "duration")
    private String duration = "30s";

    @Option(names = "--thread", description = "number of threads")
    private Integer numThreads = 5;

    @Option(names = "--url", required = true, description = "OCSP responder URL")
    private String serverUrl;

    @Option(names = "--max-num", description = "maximal number of OCSP queries, 0 for unlimited")
    private Integer maxRequests = 0;

    @Option(names = "--nonce", description = "use nonce")
    private Boolean useNonce = Boolean.FALSE;

    @Option(names = "--nonce-len", description = "nonce length in octets")
    private Integer nonceLen;

    @Option(names = "--allow-no-nonce-in-resp", description = "allow response without nonce")
    private Boolean allowNoNonceInResponse = Boolean.FALSE;

    @Option(names = "--hash", description = "hash algorithm name")
    @Completion(Completers.HashAlgoCompleter.class)
    private String hashAlgo = "SHA256";

    @Option(names = "--sig-alg", split = ",", description = "preferred signature algorithms")
    @Completion(Completers.SigAlgoCompleter.class)
    private List<String> prefSigAlgs;

    @Option(names = "--http-get", description = "use HTTP GET for small request")
    private Boolean useHttpGetForSmallRequest = Boolean.FALSE;

    @Option(names = "--sign", description = "sign request")
    private Boolean signRequest = Boolean.FALSE;

    @Override
    public void run() {
      Iterator<BigInteger> serialNumberIterator = null;
      try {
        int specified = 0;
        if (serialNumberList != null) {
          specified++;
        }
        if (serialNumberFile != null) {
          specified++;
        }
        if (CollectionUtil.isNotEmpty(certFiles)) {
          specified++;
        }
        if (specified != 1) {
          throw new IllegalArgumentException(
              "exactly one of serial, serial-file and cert must be specified");
        }
        if (numThreads == null || numThreads < 1) {
          throw new IllegalArgumentException("invalid number of threads " + numThreads);
        }

        if (serialNumberFile != null) {
          serialNumberIterator = new FileBigIntegerIterator(
              IoUtil.expandFilepath(serialNumberFile), hex, true);
        } else {
          List<BigIntegerRange> serialNumbers = new ArrayList<>();
          if (serialNumberList != null) {
            for (String token : serialNumberList.split("[, ]+")) {
              if (StringUtil.isBlank(token)) {
                continue;
              }
              String[] parts = token.split("-", 2);
              BigInteger from = toBigInt(parts[0], hex);
              BigInteger to = parts.length == 2 ? toBigInt(parts[1], hex) : from;
              serialNumbers.add(new BigIntegerRange(from, to));
            }
          } else {
            for (String certFile : certFiles) {
              X509Cert cert = X509Util.parseCert(new File(certFile));
              BigInteger serial = cert.serialNumber();
              serialNumbers.add(new BigIntegerRange(serial, serial));
            }
          }
          serialNumberIterator = new RangeBigIntegerIterator(serialNumbers, true);
        }

        RequestOptions options = new RequestOptions();
        options.setUseNonce(useNonce);
        if (nonceLen != null) {
          options.setNonceLen(nonceLen);
        }
        options.setAllowNoNonceInResponse(allowNoNonceInResponse);
        options.setHashAlgorithm(HashAlgo.getInstance(hashAlgo));
        options.setSignRequest(signRequest);
        options.setUseHttpGetForRequest(useHttpGetForSmallRequest);
        if (CollectionUtil.isNotEmpty(prefSigAlgs)) {
          SignAlgo[] algos = new SignAlgo[prefSigAlgs.size()];
          for (int i = 0; i < algos.length; i++) {
            algos[i] = SignAlgo.getInstance(prefSigAlgs.get(i));
          }
          options.setPreferredSignatureAlgorithms(algos);
        }

        String description = StringUtil.concatObjects(
            "issuer cert: ", issuerCertFile, "\nserver URL: ", serverUrl,
            "\nmaxRequest: ", maxRequests, "\nhash: ", hashAlgo);

        X509Cert issuerCert = X509Util.parseCert(new File(issuerCertFile));
        PkiClientRuntime.getOcspRequestor();
        OcspBenchmark benchmark = new OcspBenchmark(
            issuerCert, serverUrl, options, serialNumberIterator, maxRequests, description);
        benchmark.setDuration(duration).setThreads(numThreads).execute();
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not run OCSP benchmark: " + ex.getMessage(), ex);
      } finally {
        if (serialNumberIterator instanceof FileBigIntegerIterator) {
          ((FileBigIntegerIterator) serialNumberIterator).close();
        }
      }
    }
  }

  private static void formatValidationIssue(
      ValidationIssue issue, String prefix, StringBuilder sb) {
    sb.append(prefix).append(issue.getCode()).append(", ").append(issue.getDescription());
    sb.append(", ").append(issue.isFailed() ? "failed" : "successful");
    if (issue.getFailureMessage() != null) {
      sb.append(", ").append(issue.getFailureMessage());
    }
  }
}
