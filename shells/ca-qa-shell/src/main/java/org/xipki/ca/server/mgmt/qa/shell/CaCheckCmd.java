/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.ca.server.mgmt.qa.shell;

import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.ca.server.mgmt.api.ValidityMode;
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
            List<String> ex = ey.caCertUris();
            List<String> is = ca.cacertUris();
            MgmtQaShellUtil.assertEquals("CA cert URIs", ex, is);
        }

        // CA certificate
        if (ey.cert() != null) {
            X509Certificate ex = ey.cert();
            X509Certificate is = ca.certificate();
            if (!ex.equals(is)) {
                throw new CmdFailure("CA cert is not as expected");
            }
        }

        // SN size
        if (ey.serialNoBitLen() != null) {
            Integer ex = ey.serialNoBitLen();
            int is = ca.serialNoBitLen();
            if (!ex.equals(is)) {
                throw buildUnexpectedException("serial number bit length", is, ex);
            }
        }

        // CMP control name
        if (ey.cmpControlName() != null) {
            String ex = ey.cmpControlName();
            String is = ca.cmpControlName();
            MgmtQaShellUtil.assertEquals("CMP control name", ex, is);
        }

        // CRL signer name
        if (ey.crlSignerName() != null) {
            String ex = ey.crlSignerName();
            String is = ca.crlSignerName();
            MgmtQaShellUtil.assertEquals("CRL signer name", ex, is);
        }

        // CRL uris
        if (ey.crlUris() != null) {
            List<String> ex = ey.crlUris();
            List<String> is = ca.crlUris();
            MgmtQaShellUtil.assertEquals("CRL URIs", ex, is);
        }

        // DeltaCRL uris
        if (ey.deltaCrlUris() != null) {
            List<String> ex = ey.deltaCrlUris();
            List<String> is = ca.deltaCrlUris();
            MgmtQaShellUtil.assertEquals("Delta CRL URIs", ex, is);
        }

        // Duplicate key mode
        if (ey.duplicateKeyPermitted() != null) {
            boolean ex = ey.duplicateKeyPermitted().booleanValue();
            boolean is = ca.isDuplicateKeyPermitted();
            if (ex != is) {
                throw buildUnexpectedException("Duplicate key permitted", is, ex);
            }
        }

        // Duplicate subject mode
        if (ey.duplicateSubjectPermitted() != null) {
            boolean ex = ey.duplicateSubjectPermitted().booleanValue();
            boolean is = ca.isDuplicateSubjectPermitted();
            if (ex != is) {
                throw buildUnexpectedException("Duplicate subject mode", is, ex);
            }
        }

        // Expiration period
        if (ey.expirationPeriod() != null) {
            Integer ex = ey.expirationPeriod();
            Integer is = ca.expirationPeriod();
            if (!ex.equals(is)) {
                throw buildUnexpectedException("Expiration period", is, ex);
            }
        }

        // Extra control
        if (ey.extraControl() != null) {
            String ex = ey.extraControl();
            String is = ca.extraControl();
            if (!ex.equals(is)) {
                throw buildUnexpectedException("Extra control", is, ex);
            }
        }

        // Max validity
        if (ey.maxValidity() != null) {
            CertValidity ex = ey.maxValidity();
            CertValidity is = ca.maxValidity();
            if (!ex.equals(is)) {
                throw buildUnexpectedException("Max validity", is, ex);
            }
        }

        // Keep expired certificate
        if (ey.keepExpiredCertInDays() != null) {
            Integer ex = ey.keepExpiredCertInDays();
            int is = ca.keepExpiredCertInDays();
            if (ex.intValue() != is) {
                throw buildUnexpectedException("keepExiredCertInDays", is, ex);
            }
        }

        // Num CRLs
        if (ey.numCrls() != null) {
            int ex = ey.numCrls();
            int is = ca.numCrls();
            if (ex != is) {
                throw buildUnexpectedException("num CRLs", is, ex);
            }
        }

        // OCSP uris
        if (ey.ocspUris() != null) {
            List<String> ex = ey.ocspUris();
            List<String> is = ca.ocspUris();
            MgmtQaShellUtil.assertEquals("OCSP URIs", ex, is);
        }

        // Permissions
        if (ey.permission() != null) {
            int ex = ey.permission();
            int is = ca.permission();
            if (ex != is) {
                throw buildUnexpectedException("permission", is, ex);
            }
        }

        // Responder name
        if (ey.responderName() != null) {
            String ex = ey.responderName();
            String is = ca.responderName();
            MgmtQaShellUtil.assertEquals("responder name", ex, is);
        }

        // Signer Type
        if (ey.signerType() != null) {
            String ex = ey.signerType();
            String is = ca.signerType();
            MgmtQaShellUtil.assertEquals("signer type", ex, is);
        }

        if (ey.signerConf() != null) {
            ConfPairs ex = new ConfPairs(ey.signerConf());
            ex.removePair("keystore");
            ConfPairs is = new ConfPairs(ca.signerConf());
            is.removePair("keystore");
            if (!ex.equals(is)) {
                throw buildUnexpectedException("signer conf", is, ex);
            }
        }

        // Status
        if (ey.status() != null) {
            CaStatus ex = ey.status();
            CaStatus is = ca.status();
            if (!ex.equals(is)) {
                throw buildUnexpectedException("status", is, ex);
            }
        }

        // validity mode
        if (ey.validityMode() != null) {
            ValidityMode ex = ey.validityMode();
            ValidityMode is = ca.validityMode();
            if (!ex.equals(is)) {
                throw buildUnexpectedException("validity mode", is, ex);
            }
        }

        println(" checked CA" + caName);
        return null;
    } // method execute0

    private CmdFailure buildUnexpectedException(final String field, final Object is,
            final Object expected) {
        return new CmdFailure(field + ": is '" + is + "', but expected '" + expected + "'");
    }

}
