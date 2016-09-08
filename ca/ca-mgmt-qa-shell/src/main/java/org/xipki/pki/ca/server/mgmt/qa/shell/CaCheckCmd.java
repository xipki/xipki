/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.pki.ca.server.mgmt.qa.shell;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.console.karaf.CmdFailure;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.server.mgmt.api.CaEntry;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.Permission;
import org.xipki.pki.ca.server.mgmt.api.ValidityMode;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509ChangeCaEntry;
import org.xipki.pki.ca.server.mgmt.shell.CaUpdateCmd;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-caqa", name = "ca-check",
        description = "check information of CAs (QA)")
@Service
public class CaCheckCmd extends CaUpdateCmd {

    @Override
    protected Object doExecute() throws Exception {
        X509ChangeCaEntry ey = getChangeCaEntry();
        String caName = ey.getName();
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
        if (ey.getCaCertUris() != null) {
            List<String> ex = ey.getCaCertUris();
            List<String> is = ca.getCacertUris();
            MgmtQaShellUtil.assertEquals("CA cert uris", ex, is);
        }

        // CA certificate
        if (ey.getCert() != null) {
            X509Certificate ex = ey.getCert();
            X509Certificate is = ca.getCertificate();
            if (!ex.equals(is)) {
                throw new CmdFailure("CA cert is not as expected");
            }
        }

        // SN size
        if (ey.getSerialNoBitLen() != null) {
            Integer ex = ey.getSerialNoBitLen();
            int is = ca.getSerialNoBitLen();
            if (!ex.equals(is)) {
                throw buildUnexpectedException("serial number bit length", is, ex);
            }
        }

        // CMP control name
        if (ey.getCmpControlName() != null) {
            String ex = ey.getCmpControlName();
            String is = ca.getCmpControlName();
            MgmtQaShellUtil.assertEquals("CMP control name", ex, is);
        }

        // CRL signer name
        if (ey.getCrlSignerName() != null) {
            String ex = ey.getCrlSignerName();
            String is = ca.getCrlSignerName();
            MgmtQaShellUtil.assertEquals("CRL signer name", ex, is);
        }

        // CRL uris
        if (ey.getCrlUris() != null) {
            List<String> ex = ey.getCrlUris();
            List<String> is = ca.getCrlUris();
            MgmtQaShellUtil.assertEquals("CRL uris", ex, is);
        }

        // DeltaCRL uris
        if (ey.getDeltaCrlUris() != null) {
            List<String> ex = ey.getDeltaCrlUris();
            List<String> is = ca.getDeltaCrlUris();
            MgmtQaShellUtil.assertEquals("Delta CRL uris", ex, is);
        }

        // Duplicate key mode
        if (ey.getDuplicateKeyPermitted() != null) {
            boolean ex = ey.getDuplicateKeyPermitted().booleanValue();
            boolean is = ca.isDuplicateKeyPermitted();
            if (ex != is) {
                throw buildUnexpectedException("Duplicate key permitted", is, ex);
            }
        }

        // Duplicate subject mode
        if (ey.getDuplicateSubjectPermitted() != null) {
            boolean ex = ey.getDuplicateSubjectPermitted().booleanValue();
            boolean is = ca.isDuplicateSubjectPermitted();
            if (ex != is) {
                throw buildUnexpectedException("Duplicate subject mode", is, ex);
            }
        }

        // Expiration period
        if (ey.getExpirationPeriod() != null) {
            Integer ex = ey.getExpirationPeriod();
            Integer is = ca.getExpirationPeriod();
            if (!ex.equals(is)) {
                throw buildUnexpectedException("Expiration period", is, ex);
            }
        }

        // Extra control
        if (ey.getExtraControl() != null) {
            String ex = ey.getExtraControl();
            String is = ca.getExtraControl();
            if (!ex.equals(is)) {
                throw buildUnexpectedException("Extra control", is, ex);
            }
        }

        // Max validity
        if (ey.getMaxValidity() != null) {
            CertValidity ex = ey.getMaxValidity();
            CertValidity is = ca.getMaxValidity();
            if (!ex.equals(is)) {
                throw buildUnexpectedException("Max validity", is, ex);
            }
        }

        // Keep expired certificate
        if (ey.getKeepExpiredCertInDays() != null) {
            Integer ex = ey.getKeepExpiredCertInDays();
            int is = ca.getKeepExpiredCertInDays();
            if (ex.intValue() != is) {
                throw buildUnexpectedException("KeepExiredCertInDays", is, ex);
            }
        }

        // Num CRLs
        if (ey.getNumCrls() != null) {
            int ex = ey.getNumCrls();
            int is = ca.getNumCrls();
            if (ex != is) {
                throw buildUnexpectedException("num CRLs", is, ex);
            }
        }

        // OCSP uris
        if (ey.getOcspUris() != null) {
            List<String> ex = ey.getOcspUris();
            List<String> is = ca.getOcspUris();
            MgmtQaShellUtil.assertEquals("OCSP uris", ex, is);
        }

        // Permissions
        if (ey.getPermissions() != null) {
            Set<Permission> ex = ey.getPermissions();
            Set<Permission> is = ca.getPermissions();
            MgmtQaShellUtil.assertEquals("permissions", ex, is);
        }

        // Responder name
        if (ey.getResponderName() != null) {
            String ex = ey.getResponderName();
            String is = ca.getResponderName();
            MgmtQaShellUtil.assertEquals("responder name", ex, is);
        }

        // Signer Type
        if (ey.getSignerType() != null) {
            String ex = ey.getSignerType();
            String is = ca.getSignerType();
            MgmtQaShellUtil.assertEquals("signer type", ex, is);
        }

        if (ey.getSignerConf() != null) {
            ConfPairs ex = new ConfPairs(ey.getSignerConf());
            ex.removePair("keystore");
            ConfPairs is = new ConfPairs(ca.getSignerConf());
            is.removePair("keystore");
            if (!ex.equals(is)) {
                throw buildUnexpectedException("signer conf", is, ex);
            }
        }

        // Status
        if (ey.getStatus() != null) {
            CaStatus ex = ey.getStatus();
            CaStatus is = ca.getStatus();
            if (!ex.equals(is)) {
                throw buildUnexpectedException("status", is, ex);
            }
        }

        // validity mode
        if (ey.getValidityMode() != null) {
            ValidityMode ex = ey.getValidityMode();
            ValidityMode is = ca.getValidityMode();
            if (!ex.equals(is)) {
                throw buildUnexpectedException("validity mode", is, ex);
            }
        }

        println(" checked CA" + caName);
        return null;
    } // method doExecute

    private CmdFailure buildUnexpectedException(final String field, final Object is,
            final Object expected) {
        return new CmdFailure(field + ": is '" + is + "', but expected '" + expected + "'");
    }

}
