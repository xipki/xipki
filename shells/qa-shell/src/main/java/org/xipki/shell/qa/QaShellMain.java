// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.qa;

import org.xipki.qa.ca.FillKeypool;
import org.xipki.crypto.core.KeySpec;
import org.xipki.shell.Completion;
import org.xipki.shell.PicocliShell;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.security.SecurityCompleters;
import org.xipki.shell.xi.XiShellBaseCommand;
import org.xipki.util.datasource.DataSourceFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.ArrayList;
import java.util.List;

/**
 * Qa Shell Main.
 *
 * @author Lijun Liao (xipki)
 */
public class QaShellMain {

  public static void main(String[] args) throws Exception {
    System.exit(PicocliShell.run("xipki> ", new RootCommand(), args));
  }

  @Command(name = "qa", description = "QA commands", subcommands = {
      QaFillKeyPoolCommands.FillKeypoolCommand.class,
      QaOcspCommands.BenchmarkOcspStatusCommand.class,
      QaOcspCommands.BatchOcspStatusCommand.class,
      QaOcspCommands.QaOcspStatusCommand.class,

      QaSecurityCommands.SpeedKeypairGenP11Command.class,
      QaSecurityCommands.SpeedSignP11Command.class,
      QaSecurityCommands.SpeedKeypairGenP12Command.class,
      QaSecurityCommands.SpeedSignP12Command.class,

      QaCaCommands.InitCaQaCommand.class,
      QaCaCommands.CheckCertCommand.class,
      QaCaCommands.CaAliasCheckCommand.class,
      QaCaCommands.CaCheckCommand.class,
      QaCaCommands.CaProfileCheckCommand.class,
      QaCaCommands.CaPublisherCheckCommand.class,
      QaCaCommands.CaRequestorCheckCommand.class,
      QaCaCommands.ProfileCheckCommand.class,
      QaCaCommands.PublisherCheckCommand.class,
      QaCaCommands.RequestorCheckCommand.class,
      QaCaCommands.SignerCheckCommand.class,
      QaCaCommands.BenchmarkCaGenEnrollCommand.class,
      QaCaCommands.BenchmarkEnrollCommand.class,
      QaCaNegCommands.NegCaAliasCheckCommand.class,
      QaCaNegCommands.NegCaCheckCommand.class,
      QaCaNegCommands.NegCaProfileCheckCommand.class,
      QaCaNegCommands.NegCaPublisherCheckCommand.class,
      QaCaNegCommands.NegCaRequestorCheckCommand.class,
      QaCaNegCommands.NegProfileCheckCommand.class,
      QaCaNegCommands.NegPublisherCheckCommand.class,
      QaCaNegCommands.NegRequestorCheckCommand.class,
      QaCaNegCommands.NegSignerCheckCommand.class,
      QaCaNegCommands.NegCheckCertCommand.class,
      QaCaNegCommands.NegCaAddCommand.class,
      QaCaNegCommands.NegCaaliasAddCommand.class,
      QaCaNegCommands.NegCaaliasRmCommand.class,
      QaCaNegCommands.NegCaprofileAddCommand.class,
      QaCaNegCommands.NegCaprofileRmCommand.class,
      QaCaNegCommands.NegCapubAddCommand.class,
      QaCaNegCommands.NegCapubRmCommand.class,
      QaCaNegCommands.NegCaRmCommand.class,
      QaCaNegCommands.NegCareqAddCommand.class,
      QaCaNegCommands.NegCareqRmCommand.class,
      QaCaNegCommands.NegCaRevokeCommand.class,
      QaCaNegCommands.NegCaUnrevokeCommand.class,
      QaCaNegCommands.NegCaUpCommand.class,
      QaCaNegCommands.NegEnrollCertCommand.class,
      QaCaNegCommands.NegGenRootcaCommand.class,
      QaCaNegCommands.NegProfileAddCommand.class,
      QaCaNegCommands.NegProfileRmCommand.class,
      QaCaNegCommands.NegProfileUpCommand.class,
      QaCaNegCommands.NegPublisherAddCommand.class,
      QaCaNegCommands.NegPublisherRmCommand.class,
      QaCaNegCommands.NegPublisherUpCommand.class,
      QaCaNegCommands.NegRepublishCommand.class,
      QaCaNegCommands.NegRequestorAddCommand.class,
      QaCaNegCommands.NegRequestorRmCommand.class,
      QaCaNegCommands.NegRequestorUpCommand.class,
      QaCaNegCommands.NegRmCertCommand.class,
      QaCaNegCommands.NegRevokeCertCommand.class,
      QaCaNegCommands.NegSignerAddCommand.class,
      QaCaNegCommands.NegSignerRmCommand.class,
      QaCaNegCommands.NegSignerUpCommand.class,
      QaCaNegCommands.NegUnrevokeCertCommand.class
  }, mixinStandardHelpOptions = true)
  /**
   * Root command for the QA shell.
   */
  public static class RootCommand extends XiShellBaseCommand {

    @Override
    public void run() {
      println("Use 'help' to list commands.");
    }

  }

  /**
   * The QA shell.
   *
   * @author Lijun Liao (xipki)
   */
  static class QaFillKeyPoolCommands {

    @Command(name = "fill-keypool", description = "Fill the keypool",
        mixinStandardHelpOptions = true)
    static class FillKeypoolCommand extends XiShellBaseCommand {

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

      @Option(names = "--keyspec",
          description = "KeySpecs of keypairs to be filled, absent for all")
      @Completion(SecurityCompleters.KeySpecCompleter.class)
      private List<String> keySpecs;

      @Override
      public void run() {
        try {
          if (num < 1) {
            throw new IllegalArgumentException("invalid num " + num);
          }

          List<KeySpec> keySpecList = null;
          if (keySpecs != null && !keySpecs.isEmpty()) {
            keySpecList = new ArrayList<>(keySpecs.size());
            for (String keySpec : keySpecs) {
              keySpecList.add(KeySpec.ofKeySpec(keySpec));
            }
          }

          char[] passwordChars = readPasswordIfNotSet(
              "Please enter password to encrypt the generated keypair", passwordHint);
          try (FillKeypool fillKeytool = new FillKeypool(new DataSourceFactory(), dbconfFile)) {
            fillKeytool.execute(num, encAlg, passwordChars, keySpecList);
          }
        } catch (Exception ex) {
          throw ex instanceof RuntimeException ? (RuntimeException) ex
              : new RuntimeException("could not fill keypool: " + ex.getMessage(), ex);
        }
      }
    }

  }

}
