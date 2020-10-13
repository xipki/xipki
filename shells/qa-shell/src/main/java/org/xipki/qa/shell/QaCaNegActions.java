/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.qa.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.mgmt.shell.CaActions;
import org.xipki.ca.mgmt.shell.CertActions.EnrollCert;
import org.xipki.ca.mgmt.shell.CertActions.RevokeCert;
import org.xipki.ca.mgmt.shell.CertActions.RmCert;
import org.xipki.ca.mgmt.shell.CertActions.UnrevokeCert;
import org.xipki.ca.mgmt.shell.MiscCaActions;
import org.xipki.ca.mgmt.shell.ProfileCaActions;
import org.xipki.ca.mgmt.shell.PublisherCaActions;
import org.xipki.ca.mgmt.shell.RequestorCaActions;
import org.xipki.ca.mgmt.shell.SignerCaActions;
import org.xipki.shell.CmdFailure;

/**
 * Actions of negative tests for CA.
 *
 * @author Lijun Liao
 */

public class QaCaNegActions {

  @Command(scope = "caqa", name = "neg-ca-add", description = "add CA (negative, QA)")
  @Service
  public static class NegCaAdd extends CaActions.CaAdd {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-ca-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaAdd

  @Command(scope = "caqa", name = "neg-caalias-add", description = "add CA alias (negative, QA)")
  @Service
  public static class NegCaaliasAdd extends CaActions.CaaliasAdd {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-caalias-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaaliasAdd

  @Command(scope = "caqa", name = "neg-caalias-rm", description = "remove CA alias (negative, QA)")
  @Service
  public static class NegCaaliasRm extends CaActions.CaaliasRm {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-caalias-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaaliasRm

  @Command(scope = "caqa", name = "neg-caprofile-add",
      description = "add certificate profiles to CA (negative, QA)")
  @Service
  public static class NegCaprofileAdd extends ProfileCaActions.CaprofileAdd {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-caprofile-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaprofileAdd

  @Command(scope = "caqa", name = "neg-caprofile-rm",
      description = "remove certificate profile from CA (negative, QA)")
  @Service
  public static class NegCaprofileRm extends ProfileCaActions.CaprofileRm {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-caprofile-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaprofileRm

  @Command(scope = "caqa", name = "neg-capub-add",
      description = "add publishers to CA (negative, QA)")
  @Service
  public static class NegCaPubAdd extends PublisherCaActions.CapubAdd {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-capub-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaPubAdd

  @Command(scope = "caqa", name = "neg-capub-rm",
      description = "remove publisher from CA (negative, QA)")
  @Service
  public static class NegCapubRm extends PublisherCaActions.CapubRm {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-capub-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCapubRm

  @Command(scope = "caqa", name = "neg-ca-rm", description = "remove CA (negative, QA)")
  @Service
  public static class NegCaRm extends CaActions.CaRm {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-ca-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaRm

  @Command(scope = "caqa", name = "neg-careq-add",
      description = "add requestor to CA (negative, QA)")
  @Service
  public static class NegCaReqAdd extends RequestorCaActions.CareqAdd {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-careq-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaReqAdd

  @Command(scope = "caqa", name = "neg-careq-rm",
      description = "remove requestor in CA (negative, QA)")
  @Service
  public static class NegCareqRm extends RequestorCaActions.CareqRm {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-careq-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCareqRm

  @Command(scope = "caqa", name = "neg-ca-revoke", description = "revoke CA (negative, QA)")
  @Service
  public static class NegCaRevoke extends CaActions.CaRevoke {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-ca-revoke");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaRevoke

  @Command(scope = "caqa", name = "neg-ca-unrevoke", description = "unrevoke CA (negative, QA)")
  @Service
  public static class NegCaUnrevoke extends CaActions.CaUnrevoke {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-ca-unrevoke");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaUnrevoke

  @Command(scope = "caqa", name = "neg-ca-up", description = "update CA (negative, QA)")
  @Service
  public static class NegCaUp extends CaActions.CaUp {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-ca-up");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaUp

  @Command(scope = "caqa", name = "neg-clear-publishqueue",
      description = "clear publish queue (negative, QA)")
  @Service
  public static class NegClearPublishQueue extends MiscCaActions.ClearPublishqueue {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-clear-publishqueue");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegClearPublishQueue

  @Command(scope = "caqa", name = "neg-enroll-cert",
      description = "enroll certificate (negative, QA)")
  @Service
  public static class NegEnrollCert extends EnrollCert {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-enroll-cert");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegEnrollCert

  @Command(scope = "caqa", name = "neg-gen-rootca",
      description = "generate selfsigned CA (negative, QA)")
  @Service
  public static class NegGenRootCa extends CaActions.GenRootca {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-gen-rootca");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegGenRootCa

  @Command(scope = "caqa", name = "neg-profile-add",
      description = "add certificate profile (negative, QA)")
  @Service
  public static class NegProfileAdd extends ProfileCaActions.ProfileAdd {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-profile-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegProfileAdd

  @Command(scope = "caqa", name = "neg-profile-rm", description = "remove Profile (negative, QA)")
  @Service
  public static class NegProfileRm extends ProfileCaActions.ProfileRm {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-profile-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegProfileRm

  @Command(scope = "caqa", name = "neg-profile-up",
      description = "update certificate profile (negative, QA)")
  @Service
  public static class NegProfileUp extends ProfileCaActions.ProfileUp {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-profile-up");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegProfileUp

  @Command(scope = "caqa", name = "neg-publisher-add", description = "add publisher (negative, QA)")
  @Service
  public static class NegPublisherAdd extends PublisherCaActions.PublisherAdd {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-publisher-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegPublisherAdd

  @Command(scope = "caqa", name = "neg-publisher-rm",
      description = "remove publisher (negative, QA)")
  @Service
  public static class NegPublisherRm extends PublisherCaActions.PublisherRm {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-publisher-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegPublisherRm

  @Command(scope = "caqa", name = "neg-publisher-up",
      description = "update publisher (negative, QA)")
  @Service
  public static class NegPublisherUp extends PublisherCaActions.PublisherUp {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-publisher-up");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegPublisherUp

  @Command(scope = "caqa", name = "neg-republish",
      description = "republish certificates (negative, QA)")
  @Service
  public static class NegRepublish extends MiscCaActions.Republish {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-republish");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegRepublish

  @Command(scope = "caqa", name = "neg-requestor-add", description = "add requestor (negative, QA)")
  @Service
  public static class NegRequestorAdd extends RequestorCaActions.RequestorAdd {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-requestor-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegRequestorAdd

  @Command(scope = "caqa", name = "neg-requestor-rm",
      description = "remove requestor (negative, QA)")
  @Service
  public static class NegRequestorRm extends RequestorCaActions.RequestorRm {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-requestor-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegRequestorRm

  @Command(scope = "caqa", name = "neg-requestor-up",
      description = "update requestor (negative, QA)")
  @Service
  public static class NegRequestorUp extends RequestorCaActions.RequestorUp {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-requestor-up");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegRequestorUp

  @Command(scope = "caqa", name = "neg-rm-cert", description = "remove certificate (negative, QA)")
  @Service
  public static class NegRmCert extends RmCert {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-remove-cert");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("Exception expected, but received none");
    }

  } // class NegRmCert

  @Command(scope = "caqa", name = "neg-revoke-cert",
      description = "revoke certificate (negative, QA)")
  @Service
  public static class NegRevokeCert extends RevokeCert {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-remove-cert");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("Exception expected, but received none");
    }

  } // class NegRevokeCert

  @Command(scope = "caqa", name = "neg-signer-add", description = "add signer (negative, QA)")
  @Service
  public static class NegSignerAdd extends SignerCaActions.SignerAdd {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-signer-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegSignerAdd

  @Command(scope = "caqa", name = "neg-signer-rm", description = "remove signer (negative, QA)")
  @Service
  public static class NegSignerRm extends SignerCaActions.SignerRm {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-signer-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegSignerRm

  @Command(scope = "caqa", name = "neg-signer-up", description = "update signer (negative, QA)")
  @Service
  public static class NegSignerUp extends SignerCaActions.SignerUp {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-signer-up");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegSignerUp

  @Command(scope = "caqa", name = "neg-unrevoke-cert",
      description = "unrevoke certificate (negative, QA)")
  @Service
  public static class NegUnrevokeCert extends UnrevokeCert {

    @Override
    protected Object execute0()
        throws Exception {
      println("neg-unrevoke-cert");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("Exception expected, but received none");
    }

  } // class NegUnrevokeCert

}
