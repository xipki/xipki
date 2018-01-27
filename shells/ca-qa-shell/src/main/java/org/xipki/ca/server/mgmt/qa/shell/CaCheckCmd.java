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

package org.xipki.ca.server.mgmt.qa.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.ca.server.mgmt.api.x509.X509ChangeCaEntry;
import org.xipki.ca.server.mgmt.shell.CaUpdateCmd;
import org.xipki.common.ConfPairs;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "caqa", name = "ca-check",
        description = "check information of CAs (QA)")
@Service
public class CaCheckCmd extends CaUpdateCmd {

    @Override
    protected Object execute0() throws Exception {
        X509ChangeCaEntry ey = getChangeCaEntry();
        String caName = ey.ident().name();
        println("checking CA" + caName);

        CaEntry entry = caManager.getCa(caName);
        if (entry == null) {
            throw new CmdFailure("could not find CA '" + caName + "'");
        }

        if (!(entry instanceof X509CaEntry)) {
            throw new CmdFailure("CA '" + caName + "' is not an X509-CA");
        }

        X509CaEntry ca = (X509CaEntry) entry;

        // CA cert uris
        if (ey.caCertUris() != null) {
            MgmtQaShellUtil.assertEquals("CA cert URIs", ey.caCertUris(), ca.cacertUris());
        }

        // CA certificate
        if (ey.cert() != null) {
            if (!ey.cert().equals(ca.certificate())) {
                throw new CmdFailure("CA cert is not as expected");
            }
        }

        // SN size
        if (ey.serialNoBitLen() != null) {
            assertObjEquals("serial number bit length", ey.serialNoBitLen(), ca.serialNoBitLen());
        }

        // CMP control name
        if (ey.cmpControlName() != null) {
            MgmtQaShellUtil.assertEquals("CMP control name",
                    ey.cmpControlName(), ca.cmpControlName());
        }

        // CRL signer name
        if (ey.crlSignerName() != null) {
            MgmtQaShellUtil.assertEquals("CRL signer name", ey.crlSignerName(), ca.crlSignerName());
        }

        // CRL uris
        if (ey.crlUris() != null) {
            MgmtQaShellUtil.assertEquals("CRL URIs", ey.crlUris(), ca.crlUris());
        }

        // DeltaCRL uris
        if (ey.deltaCrlUris() != null) {
            MgmtQaShellUtil.assertEquals("Delta CRL URIs", ey.deltaCrlUris(), ca.deltaCrlUris());
        }

        // Duplicate key mode
        if (ey.duplicateKeyPermitted() != null) {
            assertObjEquals("Duplicate key permitted",
                    ey.duplicateKeyPermitted(), ca.isDuplicateKeyPermitted());
        }

        // Duplicate subject mode
        if (ey.duplicateSubjectPermitted() != null) {
            assertObjEquals("Duplicate subject permitted",
                    ey.duplicateSubjectPermitted(), ca.isDuplicateSubjectPermitted());
        }

        // Expiration period
        if (ey.expirationPeriod() != null) {
            assertObjEquals("Expiration period", ey.expirationPeriod(), ca.expirationPeriod());
        }

        // Extra control
        if (ey.extraControl() != null) {
            MgmtQaShellUtil.assertEquals("Extra control", ey.extraControl(), ca.extraControl());
        }

        // Max validity
        if (ey.maxValidity() != null) {
            assertObjEquals("Max validity", ey.maxValidity(), ca.maxValidity());
        }

        // Keep expired certificate
        if (ey.keepExpiredCertInDays() != null) {
            assertObjEquals("keepExiredCertInDays",
                    ey.keepExpiredCertInDays(), ca.keepExpiredCertInDays());
        }

        // Num CRLs
        if (ey.numCrls() != null) {
            assertObjEquals("num CRLs", ey.numCrls(), ca.numCrls());
        }

        // OCSP uris
        if (ey.ocspUris() != null) {
            MgmtQaShellUtil.assertEquals("OCSP URIs", ey.ocspUris(), ca.ocspUris());
        }

        // Permissions
        if (ey.permission() != null) {
            assertObjEquals("permission", ey.permission(), ca.permission());
        }

        // Responder name
        if (ey.responderName() != null) {
            MgmtQaShellUtil.assertEquals("responder name", ey.responderName(), ca.responderName());
        }

        // Signer Type
        if (ey.signerType() != null) {
            MgmtQaShellUtil.assertEquals("signer type", ey.signerType(), ca.signerType());
        }

        if (ey.signerConf() != null) {
            ConfPairs ex = new ConfPairs(ey.signerConf());
            ex.removePair("keystore");
            ConfPairs is = new ConfPairs(ca.signerConf());
            is.removePair("keystore");
            assertObjEquals("signer conf", ex, is);
        }

        // Status
        if (ey.status() != null) {
            assertObjEquals("status", ey.status(), ca.status());
        }

        // validity mode
        if (ey.validityMode() != null) {
            assertObjEquals("validity mode", ey.validityMode(), ca.validityMode());
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
