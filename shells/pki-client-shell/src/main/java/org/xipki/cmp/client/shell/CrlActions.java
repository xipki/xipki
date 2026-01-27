// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.cert.X509CRLHolder;
import org.xipki.cmp.client.CmpClientException;
import org.xipki.cmp.client.PkiErrorException;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.XiAction;
import org.xipki.util.extra.misc.ReqRespDebug;

import java.util.Optional;

/**
 * CMP client actions related to CRL.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class CrlActions {

  @Command(scope = "xi", name = "cmp-get-crl", description = "download CRL")
  @Service
  public static class CmpGetCrl extends CrlAction {

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
    protected Object execute0() throws Exception {
      X509CRLHolder crl;
      try {
        crl = Optional.ofNullable(retrieveCrl()).orElseThrow(
                () -> new CmdFailure("received no CRL from server"));
      } catch (PkiErrorException ex) {
        throw new CmdFailure("received no CRL from server: " + ex.getMessage());
      }

      saveVerbose("saved CRL to file", outFile,
          XiAction.encodeCrl(crl.getEncoded(), outform));
      return null;
    } // method execute0

  } // class CmpGetCrl

  public abstract static class CrlAction extends CmpActions.ClientAction {

    @Option(name = "--outform", description = "output format of the CRL")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the CRL")
    @Completion(FileCompleter.class)
    protected String outFile;

    protected abstract X509CRLHolder retrieveCrl()
        throws CmpClientException, PkiErrorException;

    @Override
    protected Object execute0() throws Exception {
      X509CRLHolder crl;
      try {
        crl = Optional.ofNullable(retrieveCrl()).orElseThrow(
                () -> new CmdFailure("received no CRL from server"));
      } catch (PkiErrorException ex) {
        throw new CmdFailure("received no CRL from server: " + ex.getMessage());
      }

      saveVerbose("saved CRL to file", outFile,
          encodeCrl(crl.getEncoded(), outform));
      return null;
    } // method execute0

  } // class CrlAction

}
