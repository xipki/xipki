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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.mgmt.api.CAEntry;
import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.ca.server.mgmt.api.CAStatus;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.api.X509ChangeCAEntry;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.password.api.PasswordResolver;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ca", name = "ca-up", description="update CA")
public class CaUpdateCommand extends CaCommand
{
    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "CA name\n"
                    + "(required)")
    private String caName;

    @Option(name = "--status",
            description = "CA status")
    private String caStatus;

    @Option(name = "--ca-cert-uri",
            multiValued = true,
            description = "CA certificate URI\n"
                    + "(multi-valued)")
    private List<String> caCertUris;

    @Option(name = "--ocsp-uri",
            multiValued = true,
            description = "OCSP URI or 'NULL'\n"
                    + "(multi-valued)")
    private List<String> ocspUris;

    @Option(name = "--crl-uri",
            multiValued = true,
            description = "CRL distribution point URI or 'NULL'\n"
                    + "(multi-valued)")
    private List<String> crlUris;

    @Option(name = "--deltacrl-uri",
            multiValued = true,
            description = "delta CRL distribution point URI or 'NULL'\n"
                    + "(multi-valued)")
    private List<String> deltaCrlUris;

    @Option(name = "--permission",
            multiValued = true,
            description = "permission\n"
                    + "(multi-valued)")
    private Set<String> permissions;

    @Option(name = "--max-validity",
            description = "maximal validity")
    private String maxValidity;

    @Option(name = "--expiration-period",
            description = "days before expiration time of CA to issue certificates")
    private Integer expirationPeriod;

    @Option(name = "--crl-signer",
            description = "CRL signer name or 'NULL'")
    private String crlSignerName;

    @Option(name = "--responder",
            description = "Responder name or 'NULL'")
    private String responderName;

    @Option(name = "--cmp-control",
            description = "CMP control name or 'NULL'")
    private String cmpControlName;

    @Option(name = "--num-crls",
            description = "number of CRLs to be kept in database")
    private Integer numCrls;

    @Option(name = "--cert",
            description = "CA certificate file")
    private String certFile;

    @Option(name = "--signer-type",
            description = "CA signer type")
    private String signerType;

    @Option(name = "--signer-conf",
            description = "CA signer configuration or 'NULL'")
    private String signerConf;

    @Option(name = "--duplicate-key",
            description = "mode of duplicate key")
    private String duplicateKeyS;

    @Option(name = "--duplicate-subject",
            description = "mode of duplicate subject")
    private String duplicateSubjectS;

    @Option(name = "--validity-mode",
            description = "mode of valditity")
    private String validityModeS;

    @Option(name = "--extra-control",
            description = "extra control")
    private String extraControl;

    private PasswordResolver passwordResolver;

    public void setPasswordResolver(
            final PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }

    protected X509ChangeCAEntry getChangeCAEntry()
    throws Exception
    {
        X509ChangeCAEntry entry = new X509ChangeCAEntry(caName);
        if(caStatus != null)
        {
            entry.setStatus(CAStatus.getCAStatus(caStatus));
        }

        if(expirationPeriod != null && expirationPeriod < 0)
        {
            throw new IllegalCmdParamException("invalid expirationPeriod: " + expirationPeriod);
        } else
        {
            entry.setExpirationPeriod(expirationPeriod);
        }

        if(certFile != null)
        {
            entry.setCert(X509Util.parseCert(certFile));
        }

        if(signerConf != null)
        {
            String _signerType = signerType;
            if(_signerType == null)
            {
                CAEntry caEntry = caManager.getCA(caName);
                if(caEntry == null)
                {
                    throw new IllegalCmdParamException("please specify the signerType");
                }
                _signerType = caEntry.getSignerType();
            }

            signerConf = ShellUtil.canonicalizeSignerConf(_signerType, signerConf, passwordResolver);
            entry.setSignerConf(signerConf);
        }

        if(duplicateKeyS != null)
        {
            DuplicationMode duplicateMode = DuplicationMode.getInstance(duplicateKeyS);
            if(duplicateMode == null)
            {
                throw new IllegalCmdParamException("invalid duplication mode " + duplicateKeyS);
            }
            entry.setDuplicateKeyMode(duplicateMode);
        }

        if(duplicateSubjectS != null)
        {
            DuplicationMode duplicateMode = DuplicationMode.getInstance(duplicateSubjectS);
            if(duplicateMode == null)
            {
                throw new IllegalCmdParamException("invalid duplication mode " + duplicateSubjectS);
            }
            entry.setDuplicateSubjectMode(duplicateMode);
        }

        if (permissions != null && permissions.size() > 0)
        {
            Set<Permission> _permissions = new HashSet<>();
            for(String permission : permissions)
            {
                Permission _permission = Permission.getPermission(permission);
                if(_permission == null)
                {
                    throw new IllegalCmdParamException("invalid permission: " + permission);
                }
                _permissions.add(_permission);
            }
            entry.setPermissions(_permissions);
        }

        entry.setCrlUris(getUris(crlUris));
        entry.setDeltaCrlUris(getUris(deltaCrlUris));
        entry.setOcspUris(getUris(ocspUris));
        entry.setCacertUris(getUris(caCertUris));

        if(validityModeS != null)
        {
            ValidityMode validityMode = ValidityMode.getInstance(validityModeS);
            if(validityMode == null)
            {
                throw new IllegalCmdParamException("invalid validity mode: " + validityModeS);
            }
            entry.setValidityMode(validityMode);
        }

        if(maxValidity != null)
        {
            entry.setMaxValidity(CertValidity.getInstance(maxValidity));
        }

        if(crlSignerName != null)
        {
            entry.setCrlSignerName(crlSignerName);
        }

        if(cmpControlName != null)
        {
            entry.setCmpControlName(cmpControlName);
        }

        if(responderName != null)
        {
            entry.setResponderName(responderName);
        }

        if(extraControl != null)
        {
            entry.setExtraControl(extraControl);
        }

        if(numCrls != null)
        {
            entry.setNumCrls(numCrls);
        }

        return entry;
    }

    @Override
    protected Object _doExecute()
    throws Exception
    {
        boolean b = caManager.changeCA(getChangeCAEntry());
        output(b, "updated", "could not update", "CA " + caName);
        return null;
    }

    private static List<String> getUris(
            final List<String> uris)
    {
        if(uris == null)
        {
            return null;
        }

        boolean clearUris = false;
        if(uris != null)
        {
            for(String uri : uris)
            {
                if(CAManager.NULL.equalsIgnoreCase(uri))
                {
                    clearUris = true;
                    break;
                }
            }
        }

        if(clearUris)
        {
            return Collections.emptyList();
        }
        else
        {
            return new ArrayList<>(uris);
        }
    }
}
