/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.cmpclient.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.cmpclient.CertIdOrError;
import org.xipki.cmpclient.Requestor;
import org.xipki.security.CrlReason;
import org.xipki.security.X509Cert;
import org.xipki.security.cmp.PkiStatusInfo;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.DateUtil;
import org.xipki.util.ReqRespDebug;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.Date;

/**
 * CMP client actions to revoke, unrevoke and remove certificates.
 *
 * @author Lijun Liao
 *
 */
public class UnRevokeCertActions {

  @Command(scope = "xi", name = "cmp-revoke", description = "revoke certificate")
  @Service
  public static class CmpRevoke extends UnRevokeCertAction {

    @Option(name = "--reason", aliases = "-r", required = true, description = "CRL reason")
    @Completion(Completers.ClientCrlReasonCompleter.class)
    private String reason;

    @Option(name = "--inv-date", description = "invalidity date, UTC time of format yyyyMMddHHmmss")
    private String invalidityDateS;

    @Override
    protected Object execute0()
        throws Exception {
      if (!(certFile == null ^ getSerialNumber() == null)) {
        throw new IllegalCmdParamException("exactly one of cert and serial must be specified");
      }

      CrlReason crlReason = CrlReason.forNameOrText(reason);

      if (!CrlReason.PERMITTED_CLIENT_CRLREASONS.contains(crlReason)) {
        throw new IllegalCmdParamException("reason " + reason + " is not permitted");
      }

      CertIdOrError certIdOrError;

      Date invalidityDate = null;
      if (isNotBlank(invalidityDateS)) {
        invalidityDate = DateUtil.parseUtcTimeyyyyMMddhhmmss(invalidityDateS);
      }

      ReqRespDebug debug = getReqRespDebug();
      try {
        Requestor requestor = getRequestor();
        X509Cert caCert = getCaCert();

        if (certFile != null) {
          X509Cert cert = X509Util.parseCert(new File(certFile));
          certIdOrError = client.revokeCert(caName, requestor, caCert, cert,
              crlReason.getCode(), invalidityDate, debug);
        } else {
          certIdOrError = client.revokeCert(caName, requestor, caCert, getSerialNumber(),
              crlReason.getCode(), invalidityDate, debug);
        }
      } finally {
        saveRequestResponse(debug);
      }

      if (certIdOrError.getError() != null) {
        PkiStatusInfo error = certIdOrError.getError();
        throw new CmdFailure("revocation failed: " + error);
      } else {
        println("revoked certificate");
      }
      return null;
    } // method execute0

  } // class CmpRevoke

  @Command(scope = "xi", name = "cmp-unsuspend", description = "unsuspend certificate")
  @Service
  public static class CmpUnsuspend extends UnRevokeCertAction {

    @Override
    protected Object execute0()
        throws Exception {
      if (!(certFile == null ^ getSerialNumber() == null)) {
        throw new IllegalCmdParamException("exactly one of cert and serial must be specified");
      }

      ReqRespDebug debug = getReqRespDebug();
      CertIdOrError certIdOrError;
      try {
        Requestor requestor = getRequestor();
        X509Cert caCert = getCaCert();

        if (certFile != null) {
          X509Cert cert = X509Util.parseCert(new File(certFile));
          certIdOrError = client.unsuspendCert(caName, requestor, caCert, cert, debug);
        } else {
          certIdOrError = client.unsuspendCert(caName, requestor, caCert, getSerialNumber(), debug);
        }
      } finally {
        saveRequestResponse(debug);
      }

      if (certIdOrError.getError() != null) {
        PkiStatusInfo error = certIdOrError.getError();
        throw new CmdFailure("releasing revocation failed: " + error);
      } else {
        println("unsuspended certificate");
      }
      return null;
    } // method execute0

  } // class CmpUnsuspend

  public abstract static class UnRevokeCertAction extends Actions.AuthClientAction {

    @Option(name = "--ca-cert", required = true,
        description = "certificate file")
    @Completion(FileCompleter.class)
    private String caCertFile;

    @Option(name = "--cert", aliases = "-c",
        description = "certificate file (either cert or serial must be specified)")
    @Completion(FileCompleter.class)
    protected String certFile;

    @Option(name = "--serial", aliases = "-s",
        description = "serial number (either cert or serial must be specified)")
    private String serialNumberS;

    private BigInteger serialNumber;

    protected X509Cert getCaCert() throws CertificateException, IOException {
      return X509Util.parseCert(new File(caCertFile));
    }

    protected BigInteger getSerialNumber() {
      if (serialNumber == null) {
        if (isNotBlank(serialNumberS)) {
          this.serialNumber = toBigInt(serialNumberS);
        }
      }
      return serialNumber;
    }

  } // class UnRevRemoveCertAction

}
