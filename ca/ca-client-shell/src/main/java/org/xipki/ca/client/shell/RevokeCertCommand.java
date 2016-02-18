/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
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

package org.xipki.ca.client.shell;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.client.shell.completer.ClientCRLReasonCompleter;
import org.xipki.ca.common.CertIDOrError;
import org.xipki.ca.common.PKIStatusInfo;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "revoke", description="Revoke certificate")
@Service
public class RevokeCertCommand extends UnRevRemoveCertCommand
{
    @Option(name = "-reason",
            required = true,
            description = "Required. Reason, valid values are \n" +
                    "  0: unspecified\n" +
                    "  1: keyCompromise\n" +
                    "  3: affiliationChanged\n" +
                    "  4: superseded\n" +
                    "  5: cessationOfOperation\n" +
                    "  6: certificateHold\n" +
                    "  9: privilegeWithdrawn")
    @Completion(ClientCRLReasonCompleter.class)
    protected String reason;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(certFile == null && (caCertFile == null || serialNumber == null))
        {
            throw new IllegalCmdParamException("either cert or (cacert, serial) must be specified");
        }

        CRLReason crlReason = CRLReason.getInstance(reason);
        if(crlReason == null)
        {
            throw new IllegalCmdParamException("invalid reason " + reason);
        }

        if(CRLReason.PERMITTED_CLIENT_CRLREASONS.contains(crlReason) == false)
        {
            throw new IllegalCmdParamException("reason " + reason + " is not permitted");
        }

        CertIDOrError certIdOrError;
        if(certFile != null)
        {
            X509Certificate cert = IoCertUtil.parseCert(certFile);
            certIdOrError = raWorker.revokeCert(cert, crlReason.getCode());
        }
        else
        {
            X509Certificate caCert = IoCertUtil.parseCert(caCertFile);
            X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
            certIdOrError = raWorker.revokeCert(issuer, new BigInteger(serialNumber), crlReason.getCode());
        }

        if(certIdOrError.getError() != null)
        {
            PKIStatusInfo error = certIdOrError.getError();
            throw new CmdFailure("Revocation failed: " + error);
        }
        else
        {
            out("Revoked certificate");
        }
        return null;
    }

}
