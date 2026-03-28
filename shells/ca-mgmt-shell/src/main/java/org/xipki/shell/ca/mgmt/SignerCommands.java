// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.util.codec.Base64;
import org.xipki.util.io.IoUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.util.Optional;

/**
 * Commands to manage signers.
 *
 * @author Lijun Liao (xipki)
 */
public class SignerCommands {
  @Command(name = "signer-add", description = "add signer", mixinStandardHelpOptions = true)
  public static class SignerAddCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--name", "-n"}, required = true, description = "signer name")
    private String name;

    @Option(names = "--type", required = true, description = "signer type")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    private String type;

    @Option(names = "--conf", required = true, description = "signer conf")
    @Completion(FilePathCompleter.class)
    private String conf;

    @Option(names = "--cert", description = "signer certificate file")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Override
    public void run() {
      try {
        String base64Cert = null;
        if (certFile != null) {
          base64Cert = IoUtil.base64Encode(X509Util.parseCert(new File(certFile)).getEncoded(),
                        false);
        }

        String effectiveConf = CaMgmtUtil.canonicalizeSignerConf(type, conf);
        client().addSigner(new SignerEntry(name, type, effectiveConf, base64Cert));
        println("added signer " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not add signer " + name + ": " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "signer-info", description = "show information of signer",
      mixinStandardHelpOptions = true)
  static class SignerInfoCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", arity = "0..1", description = "signer name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    private String name;

    @Option(names = {"--verbose", "-v"}, description = "show signer information verbosely")
    private boolean verbose;

    @Override
    public void run() {
      try {
        if (name == null) {
          println(CaMgmtUtil.formatNames("signer", client().getSignerNames()));
          return;
        }

        SignerEntry entry = Optional.ofNullable(client().getSigner(name))
            .orElseThrow(() -> new CaMgmtException("could not find signer " + name));
        println(entry.toString(verbose));
      } catch (Exception ex) {
        throw new RuntimeException("could not get signer info: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "signer-rm", description = "remove signer", mixinStandardHelpOptions = true)
  public static class SignerRmCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", description = "signer name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    private String name;

    @Option(names = {"--force", "-f"}, description = "without prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        if (force || confirmAction("Do you want to remove signer " + name)) {
          client().removeSigner(name);
          println("removed signer " + name);
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not remove signer " + name + ": " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "signer-up", description = "update signer", mixinStandardHelpOptions = true)
  public static class SignerUpCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--name", "-n"}, required = true, description = "signer name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    private String name;

    @Option(names = "--type", description = "signer type")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    private String type;

    @Option(names = "--cert", description = "certificate file or null")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(names = "--conf", description = "signer conf or null")
    @Completion(FilePathCompleter.class)
    private String conf;

    @Override
    public void run() {
      try {
        String cert = null;
        if ("null".equalsIgnoreCase(certFile)) {
          cert = "null";
        } else if (certFile != null) {
          cert = Base64.encodeToString(X509Util.parseCert(new File(certFile)).getEncoded());
        }

        String effectiveType = type;
        if (effectiveType == null && conf != null) {
          SignerEntry entry = Optional.ofNullable(client().getSigner(name))
              .orElseThrow(() -> new CaMgmtException("could not find signer " + name));
          effectiveType = entry.type();
        }

        String effectiveConf = conf == null
            ? null : CaMgmtUtil.canonicalizeSignerConf(effectiveType, conf);
        client().changeSigner(name, type, effectiveConf, cert);
        println("updated signer " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not update signer " + name + ": " + ex.getMessage(), ex);
      }
    }
  }
}
