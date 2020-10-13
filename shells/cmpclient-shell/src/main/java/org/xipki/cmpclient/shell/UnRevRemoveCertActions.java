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

import java.io.File;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.cmpclient.CertIdOrError;
import org.xipki.cmpclient.shell.Actions.ClientAction;
import org.xipki.security.CrlReason;
import org.xipki.security.X509Cert;
import org.xipki.security.cmp.PkiStatusInfo;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.Args;
import org.xipki.util.DateUtil;
import org.xipki.util.ReqRespDebug;

/**
 * CMP client actions to revoke, unrevoke and remove certificates.
 *
 * @author Lijun Liao
 *
 */
public class UnRevRemoveCertActions {

  @Command(scope = "xi", name = "cmp-revoke", description = "revoke certificate")
  @Service
  public static class CmpRevoke extends UnRevRemoveCertAction {

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
        if (certFile != null) {
          X509Cert cert = X509Util.parseCert(new File(certFile));
          certIdOrError = client.revokeCert(caName, cert, crlReason.getCode(), invalidityDate,
              debug);
        } else {
          certIdOrError = client.revokeCert(caName, getSerialNumber(), crlReason.getCode(),
              invalidityDate, debug);
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

  @Command(scope = "xi", name = "cmp-rm-cert", description = "remove certificate")
  @Service
  public static class CmpRmCert extends UnRevRemoveCertAction {

    @Override
    protected Object execute0()
        throws Exception {
      if (!(certFile == null ^ getSerialNumber() == null)) {
        throw new IllegalCmdParamException("exactly one of cert and serial must be specified");
      }

      ReqRespDebug debug = getReqRespDebug();
      CertIdOrError certIdOrError;
      try {
        if (certFile != null) {
          X509Cert cert = X509Util.parseCert(new File(certFile));
          certIdOrError = client.removeCert(caName, cert, debug);
        } else {
          certIdOrError = client.removeCert(caName, getSerialNumber(), debug);
        }
      } finally {
        saveRequestResponse(debug);
      }

      if (certIdOrError.getError() != null) {
        PkiStatusInfo error = certIdOrError.getError();
        throw new CmdFailure("removing certificate failed: " + error);
      } else {
        println("removed certificate");
      }
      return null;
    } // method execute0

  } // class CmpRmCert

  @Command(scope = "xi", name = "cmp-unrevoke", description = "unrevoke certificate")
  @Service
  public static class CmpUnrevoke extends UnRevRemoveCertAction {

    @Override
    protected Object execute0()
        throws Exception {
      if (!(certFile == null ^ getSerialNumber() == null)) {
        throw new IllegalCmdParamException("exactly one of cert and serial must be specified");
      }

      ReqRespDebug debug = getReqRespDebug();
      CertIdOrError certIdOrError;
      try {
        if (certFile != null) {
          X509Cert cert = X509Util.parseCert(new File(certFile));
          certIdOrError = client.unrevokeCert(caName, cert, debug);
        } else {
          certIdOrError = client.unrevokeCert(caName, getSerialNumber(), debug);
        }
      } finally {
        saveRequestResponse(debug);
      }

      if (certIdOrError.getError() != null) {
        PkiStatusInfo error = certIdOrError.getError();
        throw new CmdFailure("releasing revocation failed: " + error);
      } else {
        println("unrevoked certificate");
      }
      return null;
    } // method execute0

  } // class CmpUnrevoke

  public abstract static class UnRevRemoveCertAction extends ClientAction {

    @Option(name = "--ca", description = "CA name\n(required if more than one CA is configured)")
    @Completion(CmpClientCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(name = "--cert", aliases = "-c",
        description = "certificate file (either cert or serial must be specified)")
    @Completion(FileCompleter.class)
    protected String certFile;

    @Option(name = "--serial", aliases = "-s",
        description = "serial number (either cert or serial must be specified)")
    private String serialNumberS;

    private BigInteger serialNumber;

    protected BigInteger getSerialNumber() {
      if (serialNumber == null) {
        if (isNotBlank(serialNumberS)) {
          this.serialNumber = toBigInt(serialNumberS);
        }
      }
      return serialNumber;
    }

    protected String checkCertificate(X509Cert cert, X509Cert caCert)
        throws CertificateEncodingException {
      if (caName != null) {
        caName = caName.toLowerCase();
      }

      Args.notNull(cert, "cert");
      Args.notNull(caCert, "caCert");

      if (!cert.getIssuer().equals(caCert.getSubject())) {
        return "the given certificate is not issued by the given issuer";
      }

      byte[] caSki = caCert.getSubjectKeyId();
      byte[] aki = cert.getAuthorityKeyId();
      if (caSki != null && aki != null) {
        if (!Arrays.equals(aki, caSki)) {
          return "the given certificate is not issued by the given issuer";
        }
      }

      try {
        cert.verify(caCert.getPublicKey(), "BC");
      } catch (SignatureException ex) {
        return "could not verify the signature of given certificate by the issuer";
      } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException
          | NoSuchProviderException ex) {
        return "could not verify the signature of given certificate by the issuer: "
                  + ex.getMessage();
      }

      return null;
    } // method checkCertificate

  } // class UnRevRemoveCertAction

}
