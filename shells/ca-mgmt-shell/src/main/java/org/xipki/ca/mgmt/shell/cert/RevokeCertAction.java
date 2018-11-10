/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.mgmt.shell.cert;

import java.math.BigInteger;
import java.util.Date;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.security.CrlReason;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.completer.ClientCrlReasonCompleter;
import org.xipki.util.DateUtil;
import org.xipki.util.InvalidConfException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "revoke-cert", description = "revoke certificate")
@Service
public class RevokeCertAction extends UnRevRmCertAction {

  @Option(name = "--reason", aliases = "-r", required = true, description = "CRL reason")
  @Completion(ClientCrlReasonCompleter.class)
  private String reason;

  @Option(name = "--inv-date", description = "invalidity date, UTC time of format yyyyMMddHHmmss")
  private String invalidityDateS;

  @Override
  protected Object execute0() throws Exception {
    CrlReason crlReason = CrlReason.forNameOrText(reason);

    if (!CrlReason.PERMITTED_CLIENT_CRLREASONS.contains(crlReason)) {
      throw new InvalidConfException("reason " + reason + " is not permitted");
    }

    Date invalidityDate = null;
    if (isNotBlank(invalidityDateS)) {
      invalidityDate = DateUtil.parseUtcTimeyyyyMMddhhmmss(invalidityDateS);
    }

    BigInteger serialNo = getSerialNumber();
    String msg = "certificate (serial number = 0x" + serialNo.toString(16) + ")";
    try {
      caManager.revokeCertificate(caName, serialNo, crlReason, invalidityDate);
      println("revoked " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not revoke " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
