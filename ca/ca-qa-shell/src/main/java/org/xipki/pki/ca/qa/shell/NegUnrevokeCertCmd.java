/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.qa.shell;

import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.commons.common.RequestResponseDebug;
import org.xipki.commons.console.karaf.CmdFailure;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.client.api.CertIdOrError;
import org.xipki.pki.ca.client.shell.UnRevRemoveCertCommandSupport;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-qa", name = "neg-unrevoke",
        description = "unrevoke certificate (negative, for QA)")
@Service
public class NegUnrevokeCertCmd extends UnRevRemoveCertCommandSupport {

    @Override
    protected Object doExecute()
    throws Exception {
        if (certFile == null && (issuerCertFile == null || getSerialNumber() == null)) {
            throw new IllegalCmdParamException("either cert or (cacert, serial) must be specified");
        }

        X509Certificate caCert = null;
        if (issuerCertFile != null) {
            caCert = X509Util.parseCert(issuerCertFile);
        }

        CertIdOrError certIdOrError;
        if (certFile != null) {
            X509Certificate cert = X509Util.parseCert(certFile);
            if (caCert != null) {
                String errorMsg = checkCertificate(cert, caCert);
                if (errorMsg != null) {
                    throw new CmdFailure(errorMsg);
                }
            }
            RequestResponseDebug debug = getRequestResponseDebug();
            try {
                certIdOrError = caClient.unrevokeCert(cert, debug);
            } finally {
                saveRequestResponse(debug);
            }
        } else {
            X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
            RequestResponseDebug debug = getRequestResponseDebug();
            try {
                certIdOrError = caClient.unrevokeCert(issuer, getSerialNumber(), debug);
            } finally {
                saveRequestResponse(debug);
            }
        }

        if (certIdOrError.getError() == null) {
            throw new CmdFailure("releasing revocation successful but expected failure");
        }
        return null;
    } // method doExecute

}
