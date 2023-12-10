// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.cmp.client.CmpClient;
import org.xipki.cmp.client.Requestor;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.*;
import org.xipki.util.ReqRespDebug.ReqRespPair;
import org.xipki.util.exception.ObjectCreationException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * CMP client actions.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class Actions {

  public abstract static class AuthClientAction extends ClientAction {

    @Reference
    protected SecurityFactory securityFactory;

    @Option(name = "--signer-p12", description = "Signer PKCS#12 file")
    @Completion(FileCompleter.class)
    private String signerP12File;

    @Option(name = "--signer-p12-algo", description = "Signature algorithm of the PKCS#12 signer")
    @Completion(Completers.SigAlgCompleter.class)
    private String signerP12SigAlgo;

    @Option(name = "--signer-keyid", multiValued = true,
        description = "User, text key ID, or prefix 0x for hex-encoded key ID")
    private String signerKeyId;

    @Option(name = "--signer-password", description = "Signer password, as plaintext or PBE-encrypted.")
    private String signerPasswordHint;

    protected Requestor getRequestor()
        throws IllegalCmdParamException, ObjectCreationException, IOException, PasswordResolverException {
      if ((signerP12File == null) == (signerKeyId == null)) {
        throw new IllegalCmdParamException("Exactly one of signer-p12 and signer-keyid must be specified");
      }

      if (signerP12File != null) {
        if (signerPasswordHint == null) {
          char[] pwd = readPassword("Enter the password for " + signerP12File);
          signerPasswordHint = new String(pwd);
        }

        ConfPairs cp = new ConfPairs()
            .putPair("password", signerPasswordHint)
            .putPair("keystore", "file:" + signerP12File);

        SignerConf sc;
        if (signerP12SigAlgo == null) {
          sc = new SignerConf(cp.getEncoded(), new SignatureAlgoControl());
        } else {
          cp.putPair("algo", signerP12SigAlgo);
          sc = new SignerConf(cp.getEncoded());
        }

        ConcurrentContentSigner signer = securityFactory.createSigner("PKCS12", sc, (X509Cert)  null);
        return new Requestor.SignatureCmpRequestor(signer);
      } else {
        if (signerPasswordHint == null) {
          signerPasswordHint = new String(readPassword("Enter the password for the user/keyID " + signerKeyId));
        }
        byte[] senderKID = StringUtil.startsWithIgnoreCase(signerKeyId, "0x")
            ? Hex.decode(signerKeyId) : signerKeyId.getBytes(StandardCharsets.UTF_8);
        int iterationCount = 2048;
        return new Requestor.PbmMacCmpRequestor(resolvePassword(signerPasswordHint),
            senderKID, HashAlgo.SHA256, iterationCount, SignAlgo.HMAC_SHA256);
      }
    }

  }

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

    protected static HashAlgo getHashAlgo(String algoStr) throws ObjectCreationException {
      if (StringUtil.isBlank(algoStr)) {
        return null;
      }

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

      return new StringBuilder(filename).insert(idx, index).insert(idx, '-').toString();
    }

  } // class ClientAction

  @Command(scope = "xi", name = "cmp-cacert", description = "get CA certificate")
  @Service
  public static class CmpCacert extends ClientAction {

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    private String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the CA certificate")
    @Completion(FileCompleter.class)
    private String outFile;

    @Override
    protected Object execute0() throws Exception {
      X509Cert caCert;
      try {
        caCert = client.caCert(caName, getReqRespDebug());
      } catch (Exception ex) {
        throw new CmdFailure("Error while retrieving CA certificate: " + ex.getMessage());
      }

      if (caCert == null) {
        throw new CmdFailure("received no CA certificate");
      }

      saveVerbose("saved CA certificate to file", outFile, encodeCert(caCert.getEncoded(), outform));
      return null;
    } // method execute0

  } // class CmpCacert

  @Command(scope = "xi", name = "cmp-cacerts", description = "get CA certificate chain")
  @Service
  public static class CmpCacertchain extends ClientAction {

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the CA certificate chain")
    @Completion(FileCompleter.class)
    private String outFile;

    @Override
    protected Object execute0() throws Exception {
      List<X509Cert> caCertChain;
      try {
        caCertChain = client.caCerts(caName, getReqRespDebug());
      } catch (Exception ex) {
        throw new CmdFailure("Error while retrieving CA certificate chain: " + ex.getMessage(), ex);
      }

      if (CollectionUtil.isEmpty(caCertChain)) {
        throw new CmdFailure("received no CA certificate chain");
      }

      String encoded = X509Util.encodeCertificates(caCertChain.toArray(new X509Cert[0]));
      saveVerbose("saved CA certificate to file", outFile, StringUtil.toUtf8Bytes(encoded));
      return null;
    } // method execute0

  } // class CmpCacertchain

}
