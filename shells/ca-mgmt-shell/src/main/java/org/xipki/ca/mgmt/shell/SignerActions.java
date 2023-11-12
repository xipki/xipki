// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.shell;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.ca.mgmt.shell.CaActions.CaAction;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import java.io.File;
import java.util.*;

/**
 * Actions to manage signers.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class SignerActions {

  @Command(scope = "ca", name = "signer-add", description = "add signer")
  @Service
  public static class SignerAdd extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "signer name")
    private String name;

    @Option(name = "--type", required = true, description = "type of the signer")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    private String type;

    @Option(name = "--conf", required = true, description = "conf of the signer")
    private String conf;

    @Option(name = "--cert", description = "signer certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Override
    protected Object execute0() throws Exception {
      String base64Cert = null;
      if (certFile != null) {
        X509Cert signerCert = X509Util.parseCert(new File(certFile));
        base64Cert = IoUtil.base64Encode(signerCert.getEncoded(), false);
      }

      if (StringUtil.orEqualsIgnoreCase(type, "PKCS12", "JCEKS")) {
        conf = ShellUtil.canonicalizeSignerConf(type, conf, securityFactory);
      }

      String msg = "signer " + name;
      try {
        caManager.addSigner(new SignerEntry(name, type, conf, base64Cert));
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class SignerAdd

  @Command(scope = "ca", name = "signer-info", description = "show information of signer")
  @Service
  public static class SignerInfo extends CaAction {

    @Argument(index = 0, name = "name", description = "signer name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    private String name;

    @Option(name = "--verbose", aliases = "-v", description = "show signer information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      StringBuilder sb = new StringBuilder();

      if (name == null) {
        Set<String> names = caManager.getSignerNames();
        int size = names.size();

        if (size == 0 || size == 1) {
          sb.append((size == 0) ? "no" : "1").append(" signer is configured\n");
        } else {
          sb.append(size).append(" signers are configured:\n");
        }

        List<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);

        for (String entry : sorted) {
          sb.append("\t").append(entry).append("\n");
        }
      } else {
        SignerEntry entry = Optional.ofNullable(caManager.getSigner(name)).orElseThrow(
            () -> new CmdFailure("could not find signer " + name));
        sb.append(entry.toString(verbose));
      }

      println(sb.toString());
      return null;
    } // method execute0

  } // class SignerInfo

  @Command(scope = "ca", name = "signer-rm", description = "remove signer")
  @Service
  public static class SignerRm extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "signer name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    private String name;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      String msg = "signer " + name;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeSigner(name);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    } // method execute0

  } // class SignerRm

  @Command(scope = "ca", name = "signer-up", description = "update signer")
  @Service
  public static class SignerUp extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "signer name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    protected String name;

    @Option(name = "--type", description = "type of the signer")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    protected String type;

    @Option(name = "--cert", description = "certificate file or 'null'")
    @Completion(FileCompleter.class)
    protected String certFile;

    @Option(name = "--conf", description = "conf of the signer or 'null'")
    private String conf;

    protected String getSignerConf() throws Exception {
      if (conf == null) {
        return null;
      }
      String tmpType = type;
      if (tmpType == null) {
        SignerEntry entry = Optional.ofNullable(caManager.getSigner(name)).orElseThrow(
            () -> new IllegalCmdParamException("please specify the type"));
        tmpType = entry.getType();
      }

      return ShellUtil.canonicalizeSignerConf(tmpType, conf, securityFactory);
    } // method getSigenrConf

    @Override
    protected Object execute0() throws Exception {
      String cert = null;
      if (CaManager.NULL.equalsIgnoreCase(certFile)) {
        cert = CaManager.NULL;
      } else if (certFile != null) {
        cert = Base64.encodeToString(X509Util.parseCert(new File(certFile)).getEncoded());
      }

      String msg = "signer " + name;
      try {
        caManager.changeSigner(name, type, getSignerConf(), cert);
        println("updated " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class SignerUp

}
