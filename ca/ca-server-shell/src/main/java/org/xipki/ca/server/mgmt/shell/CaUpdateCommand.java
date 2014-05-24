/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.server.mgmt.CAManager;
import org.xipki.ca.server.mgmt.Permission;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.ConfigurationException;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "ca", name = "ca-update", description="Update CA")
public class CaUpdateCommand extends CaCommand
{
    @Option(name = "-name",
            required = true, description = "Required. CA name")
    protected String            caName;

    @Option(name = "-status",
            description = "CA status, active|pending|deactivated")
    protected String            caStatus;

    @Option(name = "-ocspUri",
            description = "OCSP URI or 'NULL', multi options is allowed",
            multiValued = true)
    protected List<String> ocspUris;

    @Option(name = "-crlUri",
            description = "CRL URI or 'NULL', multi options is allowed",
            multiValued = true)
    protected List<String> crlUris;

    @Option(name = "-permission",
            description = "Permission, multi options is allowed. allowed values are " + permissionsText,
            multiValued = true)
    protected Set<String> permissions;

    @Option(name = "-nextSerial",
            description = "Serial number for the next certificate, "
                    + "must be greater than the current nextSerial or 0 for random serial number")
    protected Long            nextSerial;

    @Option(name = "-maxValidity",
            description = "Maximal validity in days")
    protected Integer            maxValidity;

    @Option(name = "-crlSigner",
            description = "CRL signer name or 'NULL'")
    protected String            crlSignerName;

    @Option(name = "-numCrls",
            description = "Number of CRLs to be kept in database")
    protected Integer           numCrls;

    @Option(name = "-cert",
            description = "CA certificate file")
    protected String            certFile;

    @Option(name = "-signerType",
            description = "CA signer type")
    protected String            signerType;

    @Option(name = "-signerConf",
            description = "CA signer configuration or 'NULL'")
    protected String            signerConf;

    @Option(name = "-edk", aliases = { "--enableDuplicateKey" },
            description = "Allow duplicate key")
    protected Boolean           enableDuplicateKey;

    @Option(name = "-ddk", aliases = { "--disableDuplicateKey" },
            description = "Duplicate key is not allowed")
    protected Boolean           disableDuplicateKey;

    @Option(name = "-eds", aliases = { "--enableDuplicateSubject" },
            description = "Allow duplicate subject")
    protected Boolean           enableDuplicateSubject;

    @Option(name = "-dds", aliases = { "--disableDuplicateSubject" },
            description = "Duplicate subject is not allowed")
    protected Boolean           disableDuplicateSubject;

    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception
    {
        CAStatus status = null;
        if(caStatus != null)
        {
            status = CAStatus.getCAStatus(caStatus);
        }

        X509Certificate caCert = null;
        if(certFile != null)
        {
            caCert = IoCertUtil.parseCert(certFile);
        }

        if(signerConf != null)
        {
             if("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType))
             {
                 signerConf = ShellUtil.replaceFileInSignerConf(signerType, signerConf, passwordResolver);
             }
        }

        Boolean allowDuplicateKey = null;
        if(enableDuplicateKey != null || disableDuplicateKey != null)
        {
            allowDuplicateKey = isEnabled(enableDuplicateKey, disableDuplicateKey, false);
        }

        Boolean allowDuplicateSubject = null;
        if(enableDuplicateSubject != null || disableDuplicateSubject != null)
        {
            allowDuplicateSubject = isEnabled(enableDuplicateSubject, disableDuplicateSubject, false);
        }

        Set<Permission> _permissions = null;
        if (permissions != null && permissions.size() > 0)
        {
            _permissions = new HashSet<Permission>();
            for(String permission : permissions)
            {
                Permission _permission = Permission.getPermission(permission);
                if(_permission == null)
                {
                    throw new ConfigurationException("Invalid permission: " + permission);
                }
                _permissions.add(_permission);
            }
        }

        boolean clearCrlUris = false;
        if(crlUris != null)
        {
            for(String uri : crlUris)
            {
                if(CAManager.NULL.equalsIgnoreCase(uri))
                {
                    clearCrlUris = true;
                    break;
                }
            }
        }

        Set<String> _crlUris = null;

        if(clearCrlUris)
        {
            _crlUris = Collections.emptySet();
        }
        else
        {
            if(crlUris != null )
            {
                _crlUris = new HashSet<String>(crlUris);
            }
        }

        boolean clearOcspUris = false;
        if(ocspUris != null)
        {
            for(String uri : ocspUris)
            {
                if(CAManager.NULL.equalsIgnoreCase(uri))
                {
                    clearOcspUris = true;
                    break;
                }
            }
        }

        Set<String> _ocspUris = null;
        if(clearOcspUris)
        {
            _ocspUris = Collections.emptySet();
        }
        else
        {
            if (ocspUris != null)
            {
                _ocspUris = new HashSet<String>(ocspUris);
            }
        }

        caManager.changeCA(
                caName,
                status,
                nextSerial,
                caCert,
                _crlUris,
                _ocspUris,
                maxValidity,
                signerType,
                signerConf,
                crlSignerName,
                allowDuplicateKey,
                allowDuplicateSubject,
                _permissions,
                numCrls);

        return null;
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }
}
