/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.common.CertIDOrError;
import org.xipki.ca.common.PKIStatusInfo;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "revoke", description="Revoke certificate")
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
    protected String reason;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(certFile == null && (caCertFile == null || serialNumber == null))
        {
            err("either cert or (cacert, serial) must be specified");
            return null;
        }

        CRLReason crlReason = CRLReason.getInstance(reason);
        if(crlReason == null)
        {
            err("invalid reason " + reason);
            return null;
        }

        if(CRLReason.PERMITTED_CLIENT_CRLREASONS.contains(crlReason) == false)
        {
            err("reason " + reason + " is not permitted");
            return null;
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
            err("Revocation failed: " + error);
        }
        else
        {
            out("Revoked certificate");
        }
        return null;
    }

}
