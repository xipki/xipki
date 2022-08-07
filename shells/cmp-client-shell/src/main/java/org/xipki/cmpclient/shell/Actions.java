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
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.cmpclient.CmpClient;
import org.xipki.cmpclient.Requestor;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.*;
import org.xipki.util.ReqRespDebug.ReqRespPair;
import org.xipki.util.exception.ObjectCreationException;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

/**
 * CMP client actions.
 *
 * @author Lijun Liao
 *
 */
public class Actions {

  public abstract static class ClientAction extends XiAction {

    @Reference
    protected SecurityFactory securityFactory;

    @Reference
    protected CmpClient client;

    @Option(name = "--ca", required = true, description = "CA name")
    protected String caName;

    @Option(name = "--req-out", description = "where to save the request")
    @Completion(FileCompleter.class)
    private String reqout;

    @Option(name = "--resp-out", description = "where to save the response")
    @Completion(FileCompleter.class)
    private String respout;

    @Option(name = "--signer-type", description = "Signer type")
    @Completion(Completers.SignerTypeCompleter.class)
    private String signerType;

    @Option(name = "--signer-conf", description = "Signer conf")
    private String signerConf;

    @Option(name = "--signer-cert", multiValued = true, description = "Signer certificates")
    private List<String> signerCerts;

    @Option(name = "--signer-keyid", multiValued = true,
        description = "Key ID, add prefix 0x for hex-encoded value")
    private String signerKeyId;

    @Option(name = "--signer-password", description = "Password")
    private String signerPassword;

    protected Requestor getRequestor()
        throws IllegalCmdParamException, ObjectCreationException {
      if (!(signerType == null ^ signerKeyId == null)) {
        throw new IllegalCmdParamException("Exactly one of signer-type and user must be specified");
      }

      if (signerType != null) {
        if (signerConf == null) {
          throw new IllegalCmdParamException("signer-conf is not specified");
        }
        X509Cert[] certs = parseCerts(signerCerts);
        ConcurrentContentSigner signer = securityFactory.createSigner(
            signerType, new SignerConf(signerConf), certs);
        return new Requestor.SignatureCmpRequestor(signer);
      } else {
        if (signerPassword == null) {
          throw new IllegalCmdParamException("signer-password is not specified");
        }
        byte[] senderKID = StringUtil.startsWithIgnoreCase(signerKeyId, "0x")
            ? Hex.decode(signerKeyId) : signerKeyId.getBytes(StandardCharsets.UTF_8);
        int iterationCount = 2048;
        return new Requestor.PbmMacCmpRequestor(signerPassword.toCharArray(),
            senderKID, HashAlgo.SHA256, iterationCount, SignAlgo.HMAC_SHA256);
      }
    }

    private static X509Cert[] parseCerts(List<String> certFiles)
        throws IllegalCmdParamException {
      if (CollectionUtil.isEmpty(certFiles)) {
        return null;
      }

      X509Cert[] certs = new X509Cert[certFiles.size()];
      for (int i = 0; i < certFiles.size(); i++) {
        String m = certFiles.get(i);
        try {
          certs[i] = X509Util.parseCert(new File(m));
        } catch (CertificateException | IOException ex) {
          throw new IllegalCmdParamException("could not parse the certificate " + m, ex);
        }
      }
      return certs;
    }

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
      X509Cert caCert;
      try {
        caCert = client.caCert(caName, getRequestor(), getReqRespDebug());
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

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the CA certificate chain")
    @Completion(FileCompleter.class)
    private String outFile;

    @Override
    protected Object execute0()
        throws Exception {
      List<X509Cert> caCertChain;
      try {
        caCertChain = client.caCerts(caName, getRequestor(), getReqRespDebug());
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
