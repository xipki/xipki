/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

import org.apache.karaf.shell.commands.Option;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

public abstract class CaAddOrGenCommand extends CaCommand
{
    @Option(name = "-name",
            required = true,
            description = "CA name"
                    + "\nrequired")
    protected String caName;

    @Option(name = "-status",
            description = "CA status")
    protected String caStatus = "active";

    @Option(name = "-ocspUri",
            multiValued = true,
            description = "OCSP URI\n"
                    + "multi-valued")
    protected List<String> ocspUris;

    @Option(name = "-crlUri",
            multiValued = true,
            description = "CRL distribution point\n"
                    + "multi-valued")
    protected List<String> crlUris;

    @Option(name = "-deltaCrlUri",
            multiValued = true,
            description = "CRL distribution point\n"
                    + "multi-valued")
    protected List<String> deltaCrlUris;

    @Option(name = "-permission",
            required = true, multiValued = true,
            description = "permission\n"
                    + "required, multi-valued")
    protected Set<String> permissions;

    @Option(name = "-nextSerial",
            required = true,
            description = "serial number for the next certificate, 0 for random serial number\n"
                    + "required")
    protected Long nextSerial;

    @Option(name = "-nextCrlNo",
            required = true,
            description = "CRL number for the next CRL\n"
                    + "required")
    protected Integer nextCrlNumber ;

    @Option(name = "-maxValidity",
            required = true,
            description = "maximal validity\n"
                    + "required")
    protected String maxValidity;

    @Option(name = "-crlSigner",
            description = "CRL signer name")
    protected String crlSignerName;

    @Option(name = "-cmpControl",
            description = "CMP control name")
    protected String cmpControlName;

    @Option(name = "-numCrls",
            description = "number of CRLs to be kept in database")
    protected Integer numCrls = 30;

    @Option(name = "-expirationPeriod",
            description = "days before expiration time of CA to issue certificates")
    protected Integer expirationPeriod = 365;

    @Option(name = "-signerType",
            required = true,
            description = "CA signer type\n"
                    + "required")
    protected String signerType;

    @Option(name = "-signerConf",
            description = "CA signer configuration")
    protected String signerConf;

    @Option(name = "-dk", aliases = { "--duplicateKey" },
            description = "mode of duplicate key")
    protected String duplicateKeyS = "forbiddenWithinProfile";

    @Option(name = "-ds", aliases = { "--duplicateSubject" },
            description = "mode of duplicate subject")
    protected String duplicateSubjectS = "forbiddenWithinProfile";

    @Option(name = "-validityMode",
            description = "mode of valditity")
    protected String validityModeS = "STRICT";

    protected SecurityFactory securityFactory;

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    protected CertValidity getMaxValidity()
    {
        CertValidity _maxValidity = null;
        if(maxValidity != null)
        {
            _maxValidity = CertValidity.getInstance(maxValidity);
        }
        return _maxValidity;
    }
}
