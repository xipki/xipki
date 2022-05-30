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

import com.alibaba.fastjson.JSON;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.xipki.cmpclient.CmpClientException;
import org.xipki.cmpclient.PkiErrorException;
import org.xipki.cmpclient.shell.Actions.ClientAction;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.HealthCheckResult;
import org.xipki.util.ReqRespDebug;
import org.xipki.util.StringUtil;

import java.math.BigInteger;
import java.util.Set;

/**
 * CMP client actions related to CRL.
 *
 * @author Lijun Liao
 *
 */
public class CrlActions {

  @Command(scope = "xi", name = "cmp-gen-crl", description = "generate CRL")
  @Service
  public static class CmpGenCrl extends CrlAction {

    @Override
    protected X509CRLHolder retrieveCrl()
        throws CmpClientException, PkiErrorException {
      ReqRespDebug debug = getReqRespDebug();
      try {
        return client.generateCrl(caName, debug);
      } finally {
        saveRequestResponse(debug);
      }
    }

  } // class CmpGenCrl

  @Command(scope = "xi", name = "cmp-get-crl", description = "download CRL")
  @Service
  public static class CmpGetCrl extends CrlAction {

    @Option(name = "--with-basecrl",
        description = "whether to retrieve the baseCRL if the current CRL is a delta CRL")
    private Boolean withBaseCrl = Boolean.FALSE;

    @Option(name = "--basecrl-out",
        description = "where to save the baseCRL\n(defaults to <out>-baseCRL)")
    @Completion(FileCompleter.class)
    private String baseCrlOut;

    @Override
    protected X509CRLHolder retrieveCrl()
        throws CmpClientException, PkiErrorException {
      ReqRespDebug debug = getReqRespDebug();
      try {
        return client.downloadCrl(caName, debug);
      } finally {
        saveRequestResponse(debug);
      }
    }

    @Override
    protected Object execute0()
        throws Exception {
      if (caName != null) {
        caName = caName.toLowerCase();
      }

      Set<String> caNames = client.getCaNames();
      if (isEmpty(caNames)) {
        throw new IllegalCmdParamException("no CA is configured");
      }

      if (caName != null && !caNames.contains(caName)) {
        throw new IllegalCmdParamException("CA " + caName + " is not within the configured CAs "
            + caNames);
      }

      if (caName == null) {
        if (caNames.size() == 1) {
          caName = caNames.iterator().next();
        } else {
          throw new IllegalCmdParamException("no CA is specified, one of " + caNames
              + " is required");
        }
      }

      X509CRLHolder crl = null;
      try {
        crl = retrieveCrl();
      } catch (PkiErrorException ex) {
        throw new CmdFailure("received no CRL from server: " + ex.getMessage());
      }

      if (crl == null) {
        throw new CmdFailure("received no CRL from server");
      }

      saveVerbose("saved CRL to file", outFile, encodeCrl(crl.getEncoded(), outform));

      if (!withBaseCrl) {
        return null;
      }

      byte[] extnValue = X509Util.getCoreExtValue(crl.getExtensions(), Extension.deltaCRLIndicator);
      if (extnValue == null) {
        return null;
      }

      if (baseCrlOut == null) {
        baseCrlOut = outFile + "-baseCRL";
      }

      BigInteger baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();

      ReqRespDebug debug = getReqRespDebug();
      try {
        crl = client.downloadCrl(caName, baseCrlNumber, debug);
      } catch (PkiErrorException ex) {
        throw new CmdFailure("received no baseCRL from server: " + ex.getMessage());
      } finally {
        saveRequestResponse(debug);
      }

      if (crl == null) {
        throw new CmdFailure("received no baseCRL from server");
      }

      saveVerbose("saved baseCRL to file", baseCrlOut, encodeCrl(crl.getEncoded(), outform));
      return null;
    } // method execute0

  } // class CmpGetCrl

  @Command(scope = "xi", name = "cmp-health", description = "check healthy status of CA")
  @Service
  public static class CmpHealth extends ClientAction {

    @Option(name = "--ca", description = "CA name\n(required if multiple CAs are configured)")
    @Completion(CmpClientCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--verbose", aliases = "-v", description = "show status verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Override
    protected Object execute0()
        throws Exception {
      if (caName != null) {
        caName = caName.toLowerCase();
      }

      Set<String> caNames = client.getCaNames();
      if (isEmpty(caNames)) {
        throw new IllegalCmdParamException("no CA is configured");
      }

      if (caName != null && !caNames.contains(caName)) {
        throw new IllegalCmdParamException("CA " + caName + " is not within the configured CAs "
            + caNames);
      }

      if (caName == null) {
        if (caNames.size() == 1) {
          caName = caNames.iterator().next();
        } else {
          throw new IllegalCmdParamException("no CA is specified, one of " + caNames
              + " is required");
        }
      }

      HealthCheckResult healthResult = client.getHealthCheckResult(caName);
      String str = StringUtil.concat("healthy status for CA ", caName, ": ",
          (healthResult.isHealthy() ? "healthy" : "not healthy"));
      if (verbose) {
        str = StringUtil.concat(str, "\n", JSON.toJSONString(healthResult, true));
      }
      System.out.println(str);
      return null;
    } // method execute0

  } // class CmpHealth

  public abstract static class CrlAction extends ClientAction {

    @Option(name = "--ca", description = "CA name\n(required if multiple CAs are configured)")
    @Completion(CmpClientCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(name = "--outform", description = "output format of the CRL")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the CRL")
    @Completion(FileCompleter.class)
    protected String outFile;

    protected abstract X509CRLHolder retrieveCrl()
        throws CmpClientException, PkiErrorException;

    @Override
    protected Object execute0()
        throws Exception {
      if (caName != null) {
        caName = caName.toLowerCase();
      }

      Set<String> caNames = client.getCaNames();
      if (isEmpty(caNames)) {
        throw new CmdFailure("no CA is configured");
      }

      if (caName != null && !caNames.contains(caName)) {
        throw new IllegalCmdParamException("CA " + caName
            + " is not within the configured CAs " + caNames);
      }

      if (caName == null) {
        if (caNames.size() == 1) {
          caName = caNames.iterator().next();
        } else {
          throw new IllegalCmdParamException("no CA is specified, one of " + caNames
              + " is required");
        }
      }

      X509CRLHolder crl;
      try {
        crl = retrieveCrl();
      } catch (PkiErrorException ex) {
        throw new CmdFailure("received no CRL from server: " + ex.getMessage());
      }

      if (crl == null) {
        throw new CmdFailure("received no CRL from server");
      }

      saveVerbose("saved CRL to file", outFile, encodeCrl(crl.getEncoded(), outform));
      return null;
    } // method execute0

  } // class CrlAction

}
