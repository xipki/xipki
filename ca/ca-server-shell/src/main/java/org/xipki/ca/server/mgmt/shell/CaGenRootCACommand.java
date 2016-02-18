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

package org.xipki.ca.server.mgmt.shell;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.common.CAStatus;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.console.karaf.FilePathCompleter;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.security.common.ConfigurationException;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "gen-rca", description="Generate selfsigned CA")
@Service
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
    @Completion(FilePathCompleter.class)
    protected String rcaCertOutFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(nextSerial < 0)
        {
            throw new IllegalCmdParamException("invalid serial number: " + nextSerial);
        }

        if(numCrls < 0)
        {
            throw new IllegalCmdParamException("invalid numCrls: " + numCrls);
        }

        if(expirationPeriod < 0)
        {
            throw new IllegalCmdParamException("invalid expirationPeriod: " + expirationPeriod);
        }

        CAStatus status = CAStatus.getCAStatus(caStatus);
        if(status == null)
        {
            throw new IllegalCmdParamException("invalid status: " + caStatus);
        }

        DuplicationMode duplicateKey = DuplicationMode.getInstance(duplicateKeyS);
        if(duplicateKey == null)
        {
            throw new IllegalCmdParamException("invalid duplication mode: " + duplicateKeyS);
        }
        DuplicationMode duplicateSubject = DuplicationMode.getInstance(duplicateSubjectS);
        if(duplicateSubject == null)
        {
            throw new IllegalCmdParamException("invalid duplication mode: " + duplicateSubjectS);
        }

        ValidityMode validityMode = ValidityMode.getInstance(validityModeS);
        if(validityMode == null)
        {
            throw new IllegalCmdParamException("invalid validityMode: " + validityModeS);
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
                maxValidity,
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
