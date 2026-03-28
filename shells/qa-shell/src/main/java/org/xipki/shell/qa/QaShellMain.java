// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.qa;

import org.xipki.shell.PicocliShell;
import org.xipki.shell.ShellBaseCommand;
import picocli.CommandLine.Command;

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
  public static class RootCommand extends ShellBaseCommand {

    @Override
    public void run() {
      println("Use 'help' to list commands.");
    }

  }
}
