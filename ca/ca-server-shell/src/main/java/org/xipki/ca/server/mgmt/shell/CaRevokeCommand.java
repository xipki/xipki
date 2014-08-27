/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.felix.gogo.commands.Argument;
import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.CertRevocationInfo;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "ca-revoke", description="Revoke CA")
public class CaRevokeCommand extends CaCommand
{
    public static List<CRLReason> permitted_reasons = Collections.unmodifiableList(
            Arrays.asList(    new CRLReason[]
            {
                CRLReason.UNSPECIFIED, CRLReason.KEY_COMPROMISE, CRLReason.CA_COMPROMISE,
                CRLReason.AFFILIATION_CHANGED, CRLReason.SUPERSEDED, CRLReason.CESSATION_OF_OPERATION,
                CRLReason.CERTIFICATE_HOLD,    CRLReason.PRIVILEGE_WITHDRAWN}));

    @Argument(index = 0, name = "name", description = "CA name", required = true)
    protected String caName;

    @Option(name = "-reason",
            required = true,
            description = "Required. Reason, valid values are \n" +
                    "0: unspecified\n" +
                    "1: keyCompromise\n" +
                    "2: cACompromise\n" +
                    "3: affiliationChanged\n" +
                    "4: superseded\n" +
                    "5: cessationOfOperation\n" +
                    "6: certificateHold\n" +
                    "9: privilegeWithdrawn")
    protected String reason;

    @Override
    protected Object doExecute()
    throws Exception
    {

        CRLReason crlReason = CRLReason.getInstance(reason);
        if(crlReason == null)
        {
            err("invalid reason " + reason);
            return null;
        }

        if(permitted_reasons.contains(crlReason) == false)
        {
            err("reason " + reason + " is not permitted");
            return null;
        }

        if(caManager.getCANames().contains(caName) == false)
        {
            err("invalid CA name " + caName);
            return null;
        }

        CertRevocationInfo revInfo = new CertRevocationInfo(crlReason);
        caManager.revokeCa(caName, revInfo);

        return null;
    }
}
