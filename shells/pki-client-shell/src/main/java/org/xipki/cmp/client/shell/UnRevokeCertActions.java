// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.cmp.client.CertIdOrError;
import org.xipki.cmp.client.CmpClientException;
import org.xipki.cmp.client.Requestor;
import org.xipki.cmp.client.RevokeCertRequest;
import org.xipki.cmp.client.UnsuspendCertRequest;
import org.xipki.security.CrlReason;
import org.xipki.security.X509Cert;
import org.xipki.security.cmp.PkiStatusInfo;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.extra.misc.ReqRespDebug;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * CMP client actions to revoke, unrevoke and remove certificates.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class UnRevokeCertActions {

  private static class ReqInfo {

    private X509Cert caCert;

    private List<String> ids;

    private List<BigInteger> serialNumbers;

    private List<String> sources;

  }

  @Command(scope = "xi", name = "cmp-revoke", description =
      "revoke certificate")
  @Service
  public static class CmpRevoke extends UnRevokeCertAction {

    @Option(name = "--reason", aliases = "-r", required = true, description =
        "CRL reason")
    @Completion(Completers.ClientCrlReasonCompleter.class)
    private String reason;

    @Option(name = "--inv-date", description =
        "invalidity date, UTC time of format yyyyMMddHHmmss")
    private String invalidityDateS;

    @Override
    protected Object execute0() throws Exception {
      CrlReason crlReason = CrlReason.forNameOrText(reason);

      if (!CrlReason.PERMITTED_CLIENT_CRLREASONS.contains(crlReason)) {
        throw new IllegalCmdParamException(
            "reason " + reason + " is not permitted");
      }

      Instant invalidityDate = null;
      if (isNotBlank(invalidityDateS)) {
        invalidityDate = DateUtil.parseUtcTimeyyyyMMddhhmmss(invalidityDateS);
      }

      ReqInfo reqInfo = getReqInfo();

      Map<String, CertIdOrError> certIdOrErrors;

      ReqRespDebug debug = getReqRespDebug();
      try {
        Requestor requestor = getRequestor();
        X509Cert caCert = getCaCert();

        RevokeCertRequest req = new RevokeCertRequest();

        for (int i = 0; i < reqInfo.ids.size(); i++) {
          RevokeCertRequest.Entry entry = new RevokeCertRequest.Entry(
              reqInfo.ids.get(i), caCert.subject(),
              reqInfo.serialNumbers.get(i), crlReason.code(),
              invalidityDate);
          req.addRequestEntry(entry);
        }

        certIdOrErrors = client.revokeCerts(caName, requestor, req, debug);
      } finally {
        saveRequestResponse(debug);
      }

      analyseResult(true, certIdOrErrors, reqInfo);
      return null;
    } // method execute0

  } // class CmpRevoke

  @Command(scope = "xi", name = "cmp-unsuspend", description =
      "unsuspend certificate")
  @Service
  public static class CmpUnsuspend extends UnRevokeCertAction {

    @Override
    protected Object execute0() throws Exception {
      ReqInfo reqInfo = getReqInfo();

      ReqRespDebug debug = getReqRespDebug();
      Map<String, CertIdOrError> certIdOrErrors;

      try {
        Requestor requestor = getRequestor();
        X509Cert caCert = reqInfo.caCert;

        UnsuspendCertRequest req = new UnsuspendCertRequest();

        for (int i = 0; i < reqInfo.ids.size(); i++) {
          UnsuspendCertRequest.Entry entry = new UnsuspendCertRequest.Entry(
              reqInfo.ids.get(i), caCert.subject(),
              reqInfo.serialNumbers.get(i));
          req.addRequestEntry(entry);
        }

        certIdOrErrors = client.unsuspendCerts(caName, requestor, req, debug);
      } finally {
        saveRequestResponse(debug);
      }

      analyseResult(false, certIdOrErrors, reqInfo);
      return null;
    } // method execute0

  } // class CmpUnsuspend

  public abstract static class UnRevokeCertAction
      extends CmpActions.AuthClientAction {

    @Option(name = "--ca-cert", required = true, description =
        "certificate file")
    @Completion(FileCompleter.class)
    private String caCertFile;

    @Option(name = "--cert", aliases = "-c", multiValued = true,
        description = "certificate files (either cert or serial is allowed)")
    @Completion(FileCompleter.class)
    protected List<String> certFiles;

    @Option(name = "--serial", aliases = "-s", multiValued = true,
        description = "serial numbers (either cert or serial is allowed)")
    private List<String> serialNumbersS;

    private List<BigInteger> serialNumbers;

    protected X509Cert getCaCert() throws CertificateException, IOException {
      return X509Util.parseCert(new File(caCertFile));
    }

    ReqInfo getReqInfo()
        throws IllegalCmdParamException, CertificateException, IOException,
        CmpClientException {
      if (CollectionUtil.isEmpty(certFiles)
          && CollectionUtil.isEmpty(serialNumbersS)) {
        throw new IllegalCmdParamException(
            "none of cert and serial is specified");
      }

      List<String> ids = new LinkedList<>();
      List<String> sources = new LinkedList<>();
      List<BigInteger> serialNumbers = new LinkedList<>();

      X509Cert caCert = getCaCert();

      int id = 1;
      if (CollectionUtil.isNotEmpty(certFiles)) {
        for (String certFile : certFiles) {
          X509Cert cert = X509Util.parseCert(new File(certFile));
          assertIssuedByCa(cert, caCert, certFile);
          ids.add(Integer.toString(id++));
          sources.add(certFile);
          serialNumbers.add(cert.serialNumber());
        }
      }

      if (CollectionUtil.isNotEmpty(serialNumbersS)) {
        for (String serialNumber : serialNumbersS) {
          ids.add(Integer.toString(id++));
          sources.add(serialNumber);
          serialNumbers.add(toBigInt(serialNumber));
        }
      }

      ReqInfo reqInfo = new ReqInfo();
      reqInfo.caCert = caCert;
      reqInfo.ids = ids;
      reqInfo.sources = sources;
      reqInfo.serialNumbers = serialNumbers;
      return reqInfo;
    }

    void analyseResult(
        boolean revoke, Map<String, CertIdOrError> certIdOrErrors,
        ReqInfo reqInfo) throws CmdFailure {
      boolean failed = false;
      List<Integer> processedIndex = new ArrayList<>(reqInfo.sources.size());
      for (Map.Entry<String, CertIdOrError> certIdOrError
          : certIdOrErrors.entrySet()) {
        String id = certIdOrError.getKey();
        int index = reqInfo.ids.indexOf(id);

        if (index == -1) {
          failed = true;
          println("error in CMP protocol, unknown id " + id);
        } else {
          processedIndex.add(index);
          String source = reqInfo.sources.get(index);
          if (certIdOrError.getValue().error() != null) {
            failed = true;
            PkiStatusInfo error = certIdOrError.getValue().error();
            println((revoke ? "revoking" : "unsuspending") + " certificate "
                + source + " failed: " + error);
          } else {
            println((revoke ? "revoked" : "suspended") +
                " certificate " + source);
          }
        }
      }

      if (reqInfo.sources.size() != processedIndex.size()) {
        processedIndex.sort(Collections.reverseOrder());
        for (Integer index : processedIndex) {
          reqInfo.sources.remove((int) index);
        }
        failed = true;
        println("server did not process request for " + reqInfo.sources);
      }

      if (failed) {
        throw new CmdFailure("failed processing at least one certificate");
      }
    }

  }

  private static void assertIssuedByCa(
      X509Cert cert, X509Cert ca, String certDesc)
      throws CmpClientException {
    boolean issued = X509Util.issues(ca, cert);
    if (!issued) {
      throw new CmpClientException("certificate " + certDesc +
          "is not issued by the CA");
    }
  }

}
