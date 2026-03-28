// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.qa;

import org.xipki.qa.ca.FillKeypool;
import org.xipki.shell.Completion;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.util.datasource.DataSourceFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * The QA shell.
 *
 * @author Lijun Liao (xipki)
 */

class QaFillKeyPoolCommands {

  @Command(name = "fill-keypool", description = "Fill the keypool",
      mixinStandardHelpOptions = true)
  static class FillKeypoolCommand extends ShellBaseCommand {

    @Option(names = "--db-conf", required = true,
        description = "database configuration file of the keypool")
    @Completion(FilePathCompleter.class)
    private String dbconfFile;

    @Option(names = "--num", description = "number of keypairs for each keyspec")
    private int num = 10;

    @Option(names = "--enc-algo", description = "algorithm to encrypt the generated keypair")
    private String encAlg = "AES128/GCM";

    @Option(names = "--password", description = "password to encrypt the generated keypair")
    private String passwordHint;

    @Override
    public void run() {
      try {
        if (num < 1) {
          throw new IllegalArgumentException("invalid num " + num);
        }

        char[] passwordChars = readPasswordIfNotSet(
            "Please enter password to encrypt the generated keypair", passwordHint);
        try (FillKeypool fillKeytool = new FillKeypool(new DataSourceFactory(), dbconfFile)) {
          fillKeytool.execute(num, encAlg, passwordChars);
        }
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not fill keypool: " + ex.getMessage(), ex);
      }
    }
  }

}
