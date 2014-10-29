/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.List;
import java.util.Set;

import org.apache.felix.gogo.commands.Option;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

public abstract class CaAddOrGenCommand extends CaCommand
{
    @Option(name = "-name",
            required = true, description = "Required. CA name")
    protected String caName;

    @Option(name = "-status",
            description = "CA status, active|pending|deactivated")
    protected String caStatus = "active";

    @Option(name = "-ocspUri",
            description = "OCSP URI, multi options is allowed",
            multiValued = true)
    protected List<String> ocspUris;

    @Option(name = "-crlUri",
            description = "CRL URI, multi options is allowed",
            multiValued = true)
    protected List<String> crlUris;

    @Option(name = "-deltaCrlUri",
            description = "Delta CRL URI, multi options is allowed",
            multiValued = true)
    protected List<String> deltaCrlUris;

    @Option(name = "-permission",
            description = "Required. Permission, multi options is allowed. allowed values are\n"
                    + permissionsText,
            required = true, multiValued = true)
    protected Set<String> permissions;

    @Option(name = "-nextSerial",
            description = "Required. Serial number for the next certificate, 0 for random serial number",
            required = true)
    protected Long nextSerial;

    @Option(name = "-maxValidity",
            description = "Required. maximal validity in days",
            required = true)
    protected Integer maxValidity;

    @Option(name = "-crlSigner",
            description = "CRL signer name")
    protected String crlSignerName;

    @Option(name = "-numCrls",
            description = "Number of CRLs to be kept in database")
    protected Integer numCrls = 30;

    @Option(name = "-expirationPeriod",
            description = "Days before expiration time of CA to issue certificates")
    protected Integer expirationPeriod = 365;

    @Option(name = "-signerType",
            description = "Required. CA signer type",
            required = true)
    protected String signerType;

    @Option(name = "-signerConf",
            description = "CA signer configuration")
    protected String signerConf;

    @Option(name = "-dk", aliases = { "--duplicateKey" },
            description = "Mode of duplicate key.\n"
                    + "\t1: forbidden\n"
                    + "\t2: forbiddenWithinProfile\n"
                    + "\t3: allowed")
    protected String duplicateKeyS = "forbiddenWithinProfile";

    @Option(name = "-ds", aliases = { "--duplicateSubject" },
            description = "Mode of duplicate subject.\n"
                    + "\t1: forbidden\n"
                    + "\t2: forbiddenWithinProfile\n"
                    + "\t3: allowed")
    protected String duplicateSubjectS = "forbiddenWithinProfile";

    @Option(name = "-validityMode",
            description = "Mode of valditity.\n"
                    + "\tSTRICT: Reject if the notBefore + validity behinds CA's notAfter \n"
                    + "\tLAX:    notBefore + validity after CA's notAfter is permitted\n"
                    + "\tCUTOFF: notAfter of issued certificates will be set to the earlier time of\n"
                    + "\t        notBefore + validigty and CA's notAfter")
    protected String validityModeS = "STRICT";

    protected SecurityFactory securityFactory;

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }
}
