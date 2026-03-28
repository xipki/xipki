// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.xipki.shell.PicocliShell;
import org.xipki.shell.ShellBaseCommand;
import picocli.CommandLine.Command;

/**
 * CA Mgmt Shell Main.
 *
 * @author Lijun Liao (xipki)
 */
public class CaMgmtShellMain {

  public static void main(String[] args) throws Exception {
    System.exit(PicocliShell.run("xipki> ", new RootCommand(), args));
  }

  @Command(name = "ca",
      description = "CA management commands", subcommands = {
      CertCommands.ShowCertStatistics.class,
      MiscCommands.ExportConfCommand.class,
      MiscCommands.LoadConfCommand.class,
      MiscCommands.NotifyChangeCommand.class,
      MiscCommands.RepublishCommand.class,
      MiscCommands.RestartCaCommand.class,
      MiscCommands.RestartCommand.class,
      MiscCommands.SystemStatusCommand.class,
      MiscCommands.UnlockCommand.class,
      MiscCommands.CaTokenInfoP11Command.class,
      DbSchemaCommands.AddDbSchema.class,
      DbSchemaCommands.ChangeDbSchema.class,
      DbSchemaCommands.RemoveDbSchema.class,
      DbSchemaCommands.ListDbSchemas.class,
      SignerCommands.SignerAddCommand.class,
      SignerCommands.SignerInfoCommand.class,
      SignerCommands.SignerRmCommand.class,
      SignerCommands.SignerUpCommand.class,
      CaCommands.CaaliasAddCommand.class,
      CaCommands.CaaliasInfoCommand.class,
      CaCommands.CaaliasRmCommand.class,
      CaCommands.CaCertCommand.class,
      CaCommands.CaCertsCommand.class,
      CaCommands.CaInfoCommand.class,
      CaCommands.CaAddCommand.class,
      CaCommands.GenRootcaCommand.class,
      CaCommands.CaUpCommand.class,
      CaCommands.CaRmCommand.class,
      CaCommands.CaRevokeCommand.class,
      CaCommands.CaUnrevokeCommand.class,
      CertCommands.EnrollCertCommand.class,
      CertCommands.EnrollCrossCertCommand.class,
      CertCommands.CertStatusCommand.class,
      CertCommands.GenCrlCommand.class,
      CertCommands.GetCertCommand.class,
      CertCommands.GetCrlCommand.class,
      CertCommands.ListCertCommand.class,
      CertCommands.RmCertCommand.class,
      CertCommands.RevokeCertCommand.class,
      CertCommands.UnsuspendCertCommand.class,
      DbCommands.ExportCaCommand.class,
      DbCommands.ExportCaCertstoreCommand.class,
      DbCommands.DiffDigestCommand.class,
      DbCommands.SqlCommand.class,
      DbCommands.ExportOcspCommand.class,
      DbCommands.ImportCaCommand.class,
      DbCommands.ImportCaCertstoreCommand.class,
      DbCommands.ImportOcspCommand.class,
      DbCommands.ImportOcspFromCaCommand.class,
      PublisherCommands.CapubAddCommand.class,
      PublisherCommands.CapubInfoCommand.class,
      PublisherCommands.CapubRmCommand.class,
      PublisherCommands.PublisherAddCommand.class,
      PublisherCommands.PublisherExportCommand.class,
      PublisherCommands.PublisherInfoCommand.class,
      PublisherCommands.PublisherRmCommand.class,
      PublisherCommands.PublisherUpCommand.class,
      ProfileCommands.CaprofileAddCommand.class,
      ProfileCommands.CaprofileInfoCommand.class,
      ProfileCommands.CaprofileRmCommand.class,
      ProfileCommands.ProfileAddCommand.class,
      ProfileCommands.ProfileExportCommand.class,
      ProfileCommands.SimpleProfileInfoCommand.class,
      ProfileCommands.ProfileInfoCommand.class,
      ProfileCommands.ProfileRmCommand.class,
      ProfileCommands.ProfileUpCommand.class,
      ProfileCommands.ConvertProfileCommand.class,
      KeyPairGenCommands.KeypairGenAddCommand.class,
      KeyPairGenCommands.KeypairGenInfoCommand.class,
      KeyPairGenCommands.KeypairGenRmCommand.class,
      KeyPairGenCommands.KeypairGenUpCommand.class,
      RequestorCommands.CareqAddCommand.class,
      RequestorCommands.CareqInfoCommand.class,
      RequestorCommands.CareqRmCommand.class,
      RequestorCommands.RequestorAddCommand.class,
      RequestorCommands.RequestorInfoCommand.class,
      RequestorCommands.RequestorRmCommand.class,
      RequestorCommands.RequestorUpCommand.class
  }, mixinStandardHelpOptions = true)

  /**
   * Root command for the CA management shell.
   */
  public static class RootCommand extends ShellBaseCommand {

    @Override
    public void run() {
      println("Use 'help' to list commands.");
    }
  }

}
