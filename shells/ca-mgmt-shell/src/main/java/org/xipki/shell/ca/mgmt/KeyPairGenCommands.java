// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.shell.Completion;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.xi.Completers;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.util.Optional;

/**
 * Actions to manage Keypair generation entries.
 *
 * @author Lijun Liao (xipki)
 */
public class KeyPairGenCommands {
  @Command(name = "keypairgen-add", description = "add keypair generation",
      mixinStandardHelpOptions = true)
  static class KeypairGenAddCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--name", "-n"}, required = true, description = "keypair generation name")
    private String name;

    @Option(names = "--type", required = true, description = "keypair generation type")
    @Completion(Completers.KeystoreTypeCompleter.class)
    private String type;

    @Option(names = "--conf", description = "keypair generation configuration")
    private String conf;

    @Option(names = "--conf-file", description = "keypair generation configuration file")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Override
    public void run() {
      try {
        String effectiveConf = CaMgmtUtil.loadOptionalText(conf, confFile);
        client().addKeypairGen(new KeypairGenEntry(name, type, effectiveConf));
        println("added keypair generation " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not add keypair generation " + name + ": "
            + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "keypairgen-info", description = "show information of keypair generation",
      mixinStandardHelpOptions = true)
  static class KeypairGenInfoCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", arity = "0..1", description = "keypair generation name")
    @Completion(CaCompleters.KeypairGenNameCompleter.class)
    private String name;

    @Override
    public void run() {
      try {
        if (name == null) {
          println(CaMgmtUtil.formatNames("keypair generation", client().getKeypairGenNames()));
          return;
        }

        KeypairGenEntry entry = Optional.ofNullable(client().getKeypairGen(name))
            .orElseThrow(() -> new CaMgmtException(
                "no keypair generation named '" + name + "' is configured"));
        println(entry.toString());
      } catch (Exception ex) {
        throw new RuntimeException("could not get keypair generation info: "
            + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "keypairgen-rm", description = "remove keypair generation",
      mixinStandardHelpOptions = true)
  static class KeypairGenRmCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", description = "keypair generation name")
    @Completion(CaCompleters.KeypairGenNameCompleter.class)
    private String name;

    @Option(names = {"--force", "-f"}, description = "without prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        if (force || confirmAction("Do you want to remove keypair generation " + name)) {
          client().removeKeypairGen(name);
          println("removed keypair generation " + name);
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not remove keypair generation " + name + ": "
            + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "keypairgen-up", description = "update keypair generation",
      mixinStandardHelpOptions = true)
  static class KeypairGenUpCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--name", "-n"}, required = true, description = "keypair generation name")
    @Completion(CaCompleters.KeypairGenNameCompleter.class)
    private String name;

    @Option(names = "--type", description = "keypair generation type")
    @Completion(Completers.KeystoreTypeCompleter.class)
    private String type;

    @Option(names = "--conf", description = "keypair generation configuration or null")
    private String conf;

    @Option(names = "--conf-file", description = "keypair generation configuration file")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Override
    public void run() {
      try {
        if (type == null && conf == null && confFile == null) {
          throw new IllegalArgumentException("nothing to update");
        }
        String effectiveConf = CaMgmtUtil.loadOptionalText(conf, confFile);
        client().changeKeypairGen(name, type, effectiveConf);
        println("updated keypair generation " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not update keypair generation " + name + ": "
            + ex.getMessage(), ex);
      }
    }
  }
}
