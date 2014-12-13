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

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.common.ConfigurationException;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "gen-rca", description="Generate selfsigned CA")
public class CaGenRootCACommand extends CaAddOrGenCommand
{
    @Option(name = "-subject",
            description = "Required. Subject of the Root CA",
            required = true)
    protected String rcaSubject;

    @Option(name = "-profile",
            description = "Required. Profile of the Root CA",
            required = true)
    protected String rcaProfile;

    @Option(name = "-out",
            description = "Where to save the generated CA certificate")
    protected String rcaCertOutFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(nextSerial < 0)
        {
            err("invalid serial number: " + nextSerial);
            return null;
        }

        if(numCrls < 0)
        {
            err("invalid numCrls: " + numCrls);
            return null;
        }

        if(expirationPeriod < 0)
        {
            err("invalid expirationPeriod: " + expirationPeriod);
            return null;
        }

        CAStatus status = CAStatus.getCAStatus(caStatus);
        if(status == null)
        {
            err("invalid status: " + caStatus);
            return null;
        }

        DuplicationMode duplicateKey = DuplicationMode.getInstance(duplicateKeyS);
        if(duplicateKey == null)
        {
            err("invalid duplication mode: " + duplicateKeyS);
        }
        DuplicationMode duplicateSubject = DuplicationMode.getInstance(duplicateSubjectS);
        if(duplicateSubject == null)
        {
            err("invalid duplication mode: " + duplicateSubjectS);
        }

        ValidityMode validityMode = ValidityMode.getInstance(validityModeS);
        if(validityMode == null)
        {
            err("invalid validityMode: " + validityModeS);
            return null;
        }

        Set<Permission> _permissions = new HashSet<>();
        for(String permission : permissions)
        {
            Permission _permission = Permission.getPermission(permission);
            if(_permission == null)
            {
                throw new ConfigurationException("Invalid permission: " + permission);
            }
            _permissions.add(_permission);
        }

        X509Certificate rcaCert = caManager.generateSelfSignedCA(caName,
                rcaProfile,
                rcaSubject,
                status,
                nextSerial,
                crlUris,
                deltaCrlUris,
                ocspUris,
                getMaxValidity(),
                signerType,
                signerConf,
                crlSignerName,
                duplicateKey,
                duplicateSubject,
                _permissions,
                numCrls,
                expirationPeriod,
                validityMode);

        if(rcaCertOutFile != null)
        {
            saveVerbose("Saved root certificate to file", new File(rcaCertOutFile), rcaCert.getEncoded());
        }

        out("Generated root CA " + caName);
        return null;
    }

}
