/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell.cert;

import java.math.BigInteger;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.X509CA;
import org.xipki.ca.server.store.CertWithRevocationInfo;
import org.xipki.security.common.CRLReason;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "revoke-cert", description="Revoke certificate")
public class RevokeCertCommand extends CaCertCommand
{
    @Option(name = "-ca",
            required = true, description = "Required. CA name")
    protected String caName;

    @Option(name = "-serial",
            required = true,
            description = "Serial number")
    protected Long   serialNumber;

    @Option(name = "-reason",
            required = true,
            description = "Required. Reason, valid values are \n" +
                    "0: unspecified\n" +
                    "1: keyCompromise\n" +
                    "3: affiliationChanged\n" +
                    "4: superseded\n" +
                    "5: cessationOfOperation\n" +
                    "6: certificateHold\n" +
                    "9: privilegeWithdrawn")
    protected String           reason;

    @Override
    protected Object doExecute()
    throws Exception
    {
        X509CA ca = caManager.getX509CA(caName);
        if(ca == null)
        {
            System.err.println("CA " + caName + " not available");
            return null;
        }

        CRLReason crlReason = CRLReason.getInstance(reason);
        if(crlReason == null)
        {
            System.out.println("invalid reason " + reason);
            return null;
        }

        if(CRLReason.PERMITTED_CLIENT_CRLREASONS.contains(crlReason) == false)
        {
            System.err.println("reason " + reason + " is not permitted");
            return null;
        }

        CertWithRevocationInfo certWithRevInfo =
                ca.revokeCertificate(BigInteger.valueOf(serialNumber), crlReason, null);

        if(certWithRevInfo != null)
        {
            System.out.println("Revoked certificate");
        }
        else
        {
            System.out.println("Could not revoke certificate");
        }

        return null;
    }

}
