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

package org.xipki.qa.ca.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.ChangeCaEntry;
import org.xipki.ca.server.mgmt.api.CmpControl;
import org.xipki.ca.server.mgmt.shell.CaUpdateAction;
import org.xipki.shell.CmdFailure;
import org.xipki.util.ConfPairs;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "caqa", name = "ca-check", description = "check information of CAs (QA)")
@Service
public class CaCheckAction extends CaUpdateAction {

  @Override
  protected Object execute0() throws Exception {
    ChangeCaEntry ey = getChangeCaEntry();
    String caName = ey.getIdent().getName();
    println("checking CA " + caName);

    CaEntry ca = caManager.getCa(caName);
    if (ca == null) {
      throw new CmdFailure("could not find CA '" + caName + "'");
    }

    CaUris eyUris = ey.getCaUris();
    // CA cert uris
    if (eyUris != null) {
      assertObjEquals("CA URIs", ey.getCaUris(), ca.getCaUris());
    }

    // CA certificate
    if (ey.getEncodedCert() != null) {
      if (!MgmtQaShellUtil.certEquals(ey.getEncodedCert(), ca.getCert().getEncoded())) {
        throw new CmdFailure("CA cert is not as expected");
      }
    }

    // SN size
    if (ey.getSerialNoBitLen() != null) {
      assertObjEquals("serial number bit length", ey.getSerialNoBitLen(), ca.getSerialNoBitLen());
    }

    // CMP control name
    if (ey.getCmpControl() != null) {
      assertObjEquals("CMP control", new CmpControl(ey.getCmpControl()), ca.getCmpControl());
    }

    // CRL control name
    if (ey.getCrlControl() != null) {
      assertObjEquals("CRL control", new CmpControl(ey.getCrlControl()), ca.getCrlControl());
    }

    // CMP responder name
    if (ey.getCmpResponderName() != null) {
      MgmtQaShellUtil.assertEquals("CMP responder name",
          ey.getCmpResponderName(), ca.getCmpResponderName());
    }

    // SCEP responder name
    if (ey.getScepResponderName() != null) {
      MgmtQaShellUtil.assertEquals("SCEP responder name",
          ey.getScepResponderName(), ca.getScepResponderName());
    }

    // CRL signer name
    if (ey.getCrlSignerName() != null) {
      MgmtQaShellUtil.assertEquals("CRL signer name", ey.getCrlSignerName(), ca.getCrlSignerName());
    }

    // Duplicate key mode
    if (ey.getDuplicateKeyPermitted() != null) {
      assertObjEquals("Duplicate key permitted",
          ey.getDuplicateKeyPermitted(), ca.isDuplicateKeyPermitted());
    }

    // Duplicate subject mode
    if (ey.getDuplicateSubjectPermitted() != null) {
      assertObjEquals("Duplicate subject permitted",
          ey.getDuplicateSubjectPermitted(), ca.isDuplicateSubjectPermitted());
    }

    // Expiration period
    if (ey.getExpirationPeriod() != null) {
      assertObjEquals("Expiration period", ey.getExpirationPeriod(), ca.getExpirationPeriod());
    }

    // Extra control
    if (ey.getExtraControl() != null) {
      assertObjEquals("Extra control", ey.getExtraControl(), ca.getExtraControl());
    }

    // Max validity
    if (ey.getMaxValidity() != null) {
      assertObjEquals("Max validity", ey.getMaxValidity(), ca.getMaxValidity());
    }

    // Keep expired certificate
    if (ey.getKeepExpiredCertInDays() != null) {
      assertObjEquals("keepExiredCertInDays",
          ey.getKeepExpiredCertInDays(), ca.getKeepExpiredCertInDays());
    }

    // Num CRLs
    if (ey.getNumCrls() != null) {
      assertObjEquals("num CRLs", ey.getNumCrls(), ca.getNumCrls());
    }

    // Permissions
    if (ey.getPermission() != null) {
      assertObjEquals("permission", ey.getPermission(), ca.getPermission());
    }

    // Signer Type
    if (ey.getSignerType() != null) {
      MgmtQaShellUtil.assertTypeEquals("signer type", ey.getSignerType(), ca.getSignerType());
    }

    if (ey.getSignerConf() != null) {
      ConfPairs ex = new ConfPairs(ey.getSignerConf());
      ex.removePair("keystore");
      ConfPairs is = new ConfPairs(ca.getSignerConf());
      is.removePair("keystore");
      assertObjEquals("signer conf", ex, is);
    }

    // Status
    if (ey.getStatus() != null) {
      assertObjEquals("status", ey.getStatus(), ca.getStatus());
    }

    // validity mode
    if (ey.getValidityMode() != null) {
      assertObjEquals("validity mode", ey.getValidityMode(), ca.getValidityMode());
    }

    println(" checked CA" + caName);
    return null;
  } // method execute0

  public static void assertObjEquals(String desc, Object ex, Object is) throws CmdFailure {
    boolean bo = (ex == null) ? (is == null) : ex.equals(is);
    if (!bo) {
      throw new CmdFailure(desc + ": is '" + is + "', but expected '" + ex + "'");
    }
  }

}
