// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.qa;

import org.xipki.shell.ca.mgmt.CaCommands;
import org.xipki.shell.ca.mgmt.CertCommands;
import org.xipki.shell.ca.mgmt.MiscCommands;
import org.xipki.shell.ca.mgmt.ProfileCommands;
import org.xipki.shell.ca.mgmt.PublisherCommands;
import org.xipki.shell.ca.mgmt.RequestorCommands;
import org.xipki.shell.ca.mgmt.SignerCommands;
import picocli.CommandLine.Command;

/**
 * Negative QA wrappers around CA management commands.
 *
 * @author Lijun Liao (xipki)
 */
class QaCaNegCommands {

  @Command(name = "neg-check-cert", description = "check certificate (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCheckCertCommand extends QaCaCommands.CheckCertCommand {

    @Override
    public void run() {
      println("neg-check-cert");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-caalias-check", description = "check CA alias (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCaAliasCheckCommand extends QaCaCommands.CaAliasCheckCommand {

    @Override
    public void run() {
      println("neg-caalias-check");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-ca-check", description = "check CA (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCaCheckCommand extends QaCaCommands.CaCheckCommand {

    @Override
    public void run() {
      println("neg-ca-check");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-caprofile-check", description = "check CA profile (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCaProfileCheckCommand extends QaCaCommands.CaProfileCheckCommand {

    @Override
    public void run() {
      println("neg-caprofile-check");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-capub-check", description = "check CA publisher (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCaPublisherCheckCommand extends QaCaCommands.CaPublisherCheckCommand {

    @Override
    public void run() {
      println("neg-capub-check");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-careq-check", description = "check CA requestor (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCaRequestorCheckCommand extends QaCaCommands.CaRequestorCheckCommand {

    @Override
    public void run() {
      println("neg-careq-check");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-profile-check", description = "check profile (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegProfileCheckCommand extends QaCaCommands.ProfileCheckCommand {

    @Override
    public void run() {
      println("neg-profile-check");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-publisher-check", description = "check publisher (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegPublisherCheckCommand extends QaCaCommands.PublisherCheckCommand {

    @Override
    public void run() {
      println("neg-publisher-check");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-requestor-check", description = "check requestor (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegRequestorCheckCommand extends QaCaCommands.RequestorCheckCommand {

    @Override
    public void run() {
      println("neg-requestor-check");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-signer-check", description = "check signer (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegSignerCheckCommand extends QaCaCommands.SignerCheckCommand {

    @Override
    public void run() {
      println("neg-signer-check");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-ca-add", description = "add CA (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCaAddCommand extends CaCommands.CaAddCommand {

    @Override
    public void run() {
      println("neg-ca-add");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-caalias-add", description = "add CA alias (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCaaliasAddCommand extends CaCommands.CaaliasAddCommand {

    @Override
    public void run() {
      println("neg-caalias-add");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-caalias-rm", description = "remove CA alias (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCaaliasRmCommand extends CaCommands.CaaliasRmCommand {

    @Override
    public void run() {
      println("neg-caalias-rm");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-caprofile-add", description =
      "add certificate profiles to CA (negative, QA)", mixinStandardHelpOptions = true)
  static class NegCaprofileAddCommand extends ProfileCommands.CaprofileAddCommand {

    @Override
    public void run() {
      println("neg-caprofile-add");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-caprofile-rm", description =
      "remove certificate profile from CA (negative, QA)", mixinStandardHelpOptions = true)
  static class NegCaprofileRmCommand extends ProfileCommands.CaprofileRmCommand {

    @Override
    public void run() {
      println("neg-caprofile-rm");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-capub-add", description = "add publishers to CA (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCapubAddCommand extends PublisherCommands.CapubAddCommand {

    @Override
    public void run() {
      println("neg-capub-add");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-capub-rm", description = "remove publisher from CA (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCapubRmCommand extends PublisherCommands.CapubRmCommand {

    @Override
    public void run() {
      println("neg-capub-rm");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-ca-rm", description = "remove CA (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCaRmCommand extends CaCommands.CaRmCommand {

    @Override
    public void run() {
      println("neg-ca-rm");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-careq-add", description = "add requestor to CA (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCareqAddCommand extends RequestorCommands.CareqAddCommand {

    @Override
    public void run() {
      println("neg-careq-add");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-careq-rm", description = "remove requestor in CA (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCareqRmCommand extends RequestorCommands.CareqRmCommand {

    @Override
    public void run() {
      println("neg-careq-rm");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-ca-revoke", description = "revoke CA (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCaRevokeCommand extends CaCommands.CaRevokeCommand {

    @Override
    public void run() {
      println("neg-ca-revoke");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-ca-unrevoke", description = "unrevoke CA (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCaUnrevokeCommand extends CaCommands.CaUnrevokeCommand {

    @Override
    public void run() {
      println("neg-ca-unrevoke");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-ca-up", description = "update CA (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegCaUpCommand extends CaCommands.CaUpCommand {

    @Override
    public void run() {
      println("neg-ca-up");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-enroll-cert", description = "enroll certificate (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegEnrollCertCommand extends CertCommands.EnrollCertCommand {

    @Override
    public void run() {
      println("neg-enroll-cert");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-gen-rootca", description =
      "generate root CA certificate (negative, QA)", mixinStandardHelpOptions = true)
  static class NegGenRootcaCommand extends CaCommands.GenRootcaCommand {

    @Override
    public void run() {
      println("neg-gen-rootca");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-profile-add", description = "add Profile (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegProfileAddCommand extends ProfileCommands.ProfileAddCommand {

    @Override
    public void run() {
      println("neg-profile-add");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-profile-rm", description = "remove Profile (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegProfileRmCommand extends ProfileCommands.ProfileRmCommand {

    @Override
    public void run() {
      println("neg-profile-rm");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-profile-up", description = "update Profile (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegProfileUpCommand extends ProfileCommands.ProfileUpCommand {

    @Override
    public void run() {
      println("neg-profile-up");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-publisher-add", description = "add publisher (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegPublisherAddCommand extends PublisherCommands.PublisherAddCommand {

    @Override
    public void run() {
      println("neg-publisher-add");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-publisher-rm", description = "remove publisher (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegPublisherRmCommand extends PublisherCommands.PublisherRmCommand {

    @Override
    public void run() {
      println("neg-publisher-rm");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-publisher-up", description = "update publisher (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegPublisherUpCommand extends PublisherCommands.PublisherUpCommand {

    @Override
    public void run() {
      println("neg-publisher-up");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-republish", description = "republish certificates (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegRepublishCommand extends MiscCommands.RepublishCommand {

    @Override
    public void run() {
      println("neg-republish");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-requestor-add", description = "add requestor (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegRequestorAddCommand extends RequestorCommands.RequestorAddCommand {

    @Override
    public void run() {
      println("neg-requestor-add");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-requestor-rm", description = "remove requestor (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegRequestorRmCommand extends RequestorCommands.RequestorRmCommand {

    @Override
    public void run() {
      println("neg-requestor-rm");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-requestor-up", description = "update requestor (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegRequestorUpCommand extends RequestorCommands.RequestorUpCommand {

    @Override
    public void run() {
      println("neg-requestor-up");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-rm-cert", description = "remove certificate (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegRmCertCommand extends CertCommands.RmCertCommand {

    @Override
    public void run() {
      println("neg-rm-cert");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-revoke-cert", description = "revoke certificate (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegRevokeCertCommand extends CertCommands.RevokeCertCommand {

    @Override
    public void run() {
      println("neg-revoke-cert");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-signer-add", description = "add signer (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegSignerAddCommand extends SignerCommands.SignerAddCommand {

    @Override
    public void run() {
      println("neg-signer-add");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-signer-rm", description = "remove signer (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegSignerRmCommand extends SignerCommands.SignerRmCommand {

    @Override
    public void run() {
      println("neg-signer-rm");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-signer-up", description = "update signer (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegSignerUpCommand extends SignerCommands.SignerUpCommand {

    @Override
    public void run() {
      println("neg-signer-up");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }

  @Command(name = "neg-unrevoke-cert", description = "unsuspend certificate (negative, QA)",
      mixinStandardHelpOptions = true)
  static class NegUnrevokeCertCommand extends CertCommands.UnsuspendCertCommand {

    @Override
    public void run() {
      println("neg-unrevoke-cert");
      try {
        super.run();
      } catch (Exception ex) {
        return;
      }
      throw new RuntimeException("exception expected, but received none");
    }
  }
}
