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

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.commands.Option;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.mgmt.api.CAStatus;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.api.X509CAEntry;
import org.xipki.common.ConfigurationException;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

public abstract class CaAddOrGenCommand extends CaCommand
{
    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "CA name\n"
                    + "(required)")
    private String caName;

    @Option(name = "--status",
            description = "CA status")
    private String caStatus = "active";

    @Option(name = "--ocsp-uri",
            multiValued = true,
            description = "OCSP URI\n"
                    + "(multi-valued)")
    private List<String> ocspUris;

    @Option(name = "--crl-uri",
            multiValued = true,
            description = "CRL distribution point\n"
                    + "(multi-valued)")
    private List<String> crlUris;

    @Option(name = "--deltacrl-uri",
            multiValued = true,
            description = "CRL distribution point\n"
                    + "(multi-valued)")
    private List<String> deltaCrlUris;

    @Option(name = "--permission",
            required = true, multiValued = true,
            description = "permission\n"
                    + "(required, multi-valued)")
    private Set<String> permissions;

    @Option(name = "--next-serial",
            required = true,
            description = "serial number for the next certificate, 0 for random serial number\n"
                    + "(required)")
    private Long nextSerial;

    @Option(name = "--next-crl-no",
            required = true,
            description = "CRL number for the next CRL\n"
                    + "(required)")
    private Integer nextCrlNumber ;

    @Option(name = "--max-validity",
            required = true,
            description = "maximal validity\n"
                    + "(required)")
    private String maxValidity;

    @Option(name = "--crl-signer",
            description = "CRL signer name")
    private String crlSignerName;

    @Option(name = "--cmp-control",
            description = "CMP control name")
    private String cmpControlName;

    @Option(name = "--num-crls",
            description = "number of CRLs to be kept in database")
    private Integer numCrls = 30;

    @Option(name = "--expiration-period",
            description = "days before expiration time of CA to issue certificates")
    private Integer expirationPeriod = 365;

    @Option(name = "--signer-type",
            required = true,
            description = "CA signer type\n"
                    + "(required)")
    private String signerType;

    @Option(name = "--signer-conf",
            description = "CA signer configuration")
    private String signerConf;

    @Option(name = "--duplicate-key",
            description = "mode of duplicate key")
    private String duplicateKeyS = "forbiddenWithinProfile";

    @Option(name = "--duplicate-subject",
            description = "mode of duplicate subject")
    private String duplicateSubjectS = "forbiddenWithinProfile";

    @Option(name = "--validity-mode",
            description = "mode of valditity")
    private String validityModeS = "STRICT";

    protected SecurityFactory securityFactory;

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    protected X509CAEntry getCAEntry()
    throws Exception
    {
        if(nextSerial < 0)
        {
            throw new ConfigurationException("invalid serial number: " + nextSerial);
        }

        if(nextCrlNumber < 1)
        {
            throw new ConfigurationException("invalid CRL number: " + nextCrlNumber);
        }

        if(numCrls < 0)
        {
            throw new ConfigurationException("invalid numCrls: " + numCrls);
        }

        if(expirationPeriod < 0)
        {
            throw new ConfigurationException("invalid expirationPeriod: " + expirationPeriod);
        }

        CAStatus status = CAStatus.getCAStatus(caStatus);
        if(status == null)
        {
            throw new ConfigurationException("invalid status: " + caStatus);
        }

        if("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType))
        {
            signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf,
                    securityFactory.getPasswordResolver());
        }

        X509CAEntry entry = new X509CAEntry(caName, nextSerial, nextCrlNumber, signerType, signerConf,
                ocspUris, crlUris, deltaCrlUris, numCrls.intValue(), expirationPeriod.intValue());

        DuplicationMode duplicateKey = DuplicationMode.getInstance(duplicateKeyS);
        if(duplicateKey == null)
        {
            throw new ConfigurationException("invalid duplication mode: " + duplicateKeyS);
        }
        entry.setDuplicateKeyMode(duplicateKey);

        DuplicationMode duplicateSubject = DuplicationMode.getInstance(duplicateSubjectS);
        if(duplicateSubject == null)
        {
            throw new ConfigurationException("invalid duplication mode: " + duplicateSubjectS);
        }
        entry.setDuplicateSubjectMode(duplicateSubject);

        ValidityMode validityMode = ValidityMode.getInstance(validityModeS);
        if(validityMode == null)
        {
            throw new ConfigurationException("invalid validity: " + validityModeS);
        }
        entry.setValidityMode(validityMode);

        entry.setStatus(status);
        if(crlSignerName != null)
        {
            entry.setCrlSignerName(crlSignerName);
        }

        CertValidity _maxValidity = CertValidity.getInstance(maxValidity);
        entry.setMaxValidity(_maxValidity);

        if(cmpControlName != null)
        {
            entry.setCmpControlName(cmpControlName);
        }

        Set<Permission> _permissions = new HashSet<>();
        for(String permission : permissions)
        {
            Permission _permission = Permission.getPermission(permission);
            if(_permission == null)
            {
                throw new ConfigurationException("invalid permission: " + permission);
            }
            _permissions.add(_permission);
        }

        entry.setPermissions(_permissions);
        return entry;
    }

}
