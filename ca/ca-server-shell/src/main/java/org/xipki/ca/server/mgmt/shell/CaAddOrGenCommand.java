/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.server.mgmt.shell;

import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.ca.server.mgmt.shell.completer.CaStatusCompleter;
import org.xipki.ca.server.mgmt.shell.completer.CrlSignerNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.DuplicationModeCompleter;
import org.xipki.ca.server.mgmt.shell.completer.PermissionCompleter;
import org.xipki.ca.server.mgmt.shell.completer.SignerTypeCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ValidityModeCompleter;
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
    @Completion(CaStatusCompleter.class)
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
    @Completion(PermissionCompleter.class)
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
    @Completion(CrlSignerNameCompleter.class)
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
    @Completion(SignerTypeCompleter.class)
    protected String signerType;

    @Option(name = "-signerConf",
            description = "CA signer configuration")
    protected String signerConf;

    @Option(name = "-dk", aliases = { "--duplicateKey" },
            description = "Mode of duplicate key.\n"
                    + "\t1: forbidden\n"
                    + "\t2: forbiddenWithinProfile\n"
                    + "\t3: allowed")
    @Completion(DuplicationModeCompleter.class)
    protected String duplicateKeyS = "forbiddenWithinProfile";

    @Option(name = "-ds", aliases = { "--duplicateSubject" },
            description = "Mode of duplicate subject.\n"
                    + "\t1: forbidden\n"
                    + "\t2: forbiddenWithinProfile\n"
                    + "\t3: allowed")
    @Completion(DuplicationModeCompleter.class)
    protected String duplicateSubjectS = "forbiddenWithinProfile";

    @Option(name = "-validityMode",
            description = "Mode of valditity.\n"
                    + "\tSTRICT: Reject if the notBefore + validity behinds CA's notAfter \n"
                    + "\tLAX:    notBefore + validity after CA's notAfter is permitted\n"
                    + "\tCUTOFF: notAfter of issued certificates will be set to the earlier time of\n"
                    + "\t        notBefore + validigty and CA's notAfter")
    @Completion(ValidityModeCompleter.class)
    protected String validityModeS = "STRICT";

    @Reference
    protected SecurityFactory securityFactory;

}
