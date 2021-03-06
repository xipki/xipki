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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.cmpclient.CmpClient;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.CollectionUtil;
import org.xipki.util.HealthCheckResult;
import org.xipki.util.IoUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.ReqRespDebug;
import org.xipki.util.ReqRespDebug.ReqRespPair;
import org.xipki.util.StringUtil;

import com.alibaba.fastjson.JSON;

/**
 * CMP client actions.
 *
 * @author Lijun Liao
 *
 */
public class Actions {

  public abstract static class ClientAction extends XiAction {

    @Reference
    protected CmpClient client;

    @Option(name = "--req-out", description = "where to save the request")
    @Completion(FileCompleter.class)
    private String reqout;

    @Option(name = "--resp-out", description = "where to save the response")
    @Completion(FileCompleter.class)
    private String respout;

    protected static HashAlgo getHashAlgo(String algoStr)
        throws ObjectCreationException {
      try {
        return HashAlgo.getInstance(algoStr);
      } catch (NoSuchAlgorithmException ex) {
        throw new ObjectCreationException(ex.getMessage(), ex);
      }
    }

    protected ReqRespDebug getReqRespDebug() {
      boolean saveReq = isNotBlank(reqout);
      boolean saveResp = isNotBlank(respout);
      if (saveReq || saveResp) {
        return new ReqRespDebug(saveReq, saveResp);
      }
      return null;
    }

    protected void saveRequestResponse(ReqRespDebug debug) {
      boolean saveReq = isNotBlank(reqout);
      boolean saveResp = isNotBlank(respout);
      if (!saveReq && !saveResp) {
        return;
      }

      if (debug == null || debug.size() == 0) {
        return;
      }

      final int n = debug.size();
      for (int i = 0; i < n; i++) {
        ReqRespPair reqResp = debug.get(i);
        if (saveReq) {
          byte[] bytes = reqResp.getRequest();
          if (bytes != null) {
            String fn = (n == 1) ? reqout : appendIndex(reqout, i);
            try {
              IoUtil.save(fn, bytes);
            } catch (IOException ex) {
              System.err.println("IOException: " + ex.getMessage());
            }
          }
        }

        if (saveResp) {
          byte[] bytes = reqResp.getResponse();
          if (bytes != null) {
            String fn = (n == 1) ? respout : appendIndex(respout, i);
            try {
              IoUtil.save(fn, bytes);
            } catch (IOException ex) {
              System.err.println("IOException: " + ex.getMessage());
            }
          }
        }
      }
    } // method saveRequestResponse

    private static String appendIndex(String filename, int index) {
      int idx = filename.lastIndexOf('.');
      if (idx == -1 || idx == filename.length() - 1) {
        return filename + "-" + index;
      }

      StringBuilder sb = new StringBuilder(filename);
      sb.insert(idx, index);
      sb.insert(idx, '-');
      return sb.toString();
    }

  } // class ClientAction

  @Command(scope = "xi", name = "cmp-cacert", description = "get CA certificate")
  @Service
  public static class CmpCacert extends ClientAction {

    @Option(name = "--ca", description = "CA name\n(required if multiple CAs are configured)")
    @Completion(CmpClientCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the CA certificate")
    @Completion(FileCompleter.class)
    private String outFile;

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

      X509Cert caCert;
      try {
        caCert = client.getCaCert(caName);
      } catch (Exception ex) {
        throw new CmdFailure("Error while retrieving CA certificate: " + ex.getMessage());
      }

      if (caCert == null) {
        throw new CmdFailure("received no CA certificate");
      }

      saveVerbose(
          "saved CA certificate to file", outFile, encodeCert(caCert.getEncoded(), outform));
      return null;
    } // method execute0

  } // class CmpCacert

  @Command(scope = "xi", name = "cmp-cacertchain", description = "get CA certificate chain")
  @Service
  public static class CmpCacertchain extends ClientAction {

    @Option(name = "--ca", description = "CA name\n(required if multiple CAs are configured)")
    @Completion(CmpClientCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the CA certificate chain")
    @Completion(FileCompleter.class)
    private String outFile;

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

      List<X509Cert> caCertChain;
      try {
        caCertChain = client.getCaCertchain(caName);
      } catch (Exception ex) {
        throw new CmdFailure("Error while retrieving CA certificate chain: " + ex.getMessage());
      }

      if (CollectionUtil.isEmpty(caCertChain)) {
        throw new CmdFailure("received no CA certificate chain");
      }

      String encoded = X509Util.encodeCertificates(caCertChain.toArray(new X509Cert[0]));
      saveVerbose("saved CA certificate to file", outFile, StringUtil.toUtf8Bytes(encoded));
      return null;
    } // method execute0

  } // class CmpCacertchain

  @Command(scope = "xi", name = "cmp-health", description = "check healty status of CA")
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

  @Command(scope = "xi", name = "cmp-init", description = "initialize CMP client")
  @Service
  public static class CmpInit extends ClientAction {

    @Override
    protected Object execute0()
        throws Exception {
      boolean succ = client.init();
      if (succ) {
        println("CA client initialized successfully");
      } else {
        println("CA client initialization failed");
      }
      return null;
    }

  } // class CmpInit

}
