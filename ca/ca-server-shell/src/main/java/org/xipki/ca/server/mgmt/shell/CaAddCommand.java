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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.server.mgmt.CAEntry;
import org.xipki.ca.server.mgmt.Permission;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.ConfigurationException;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "ca", name = "ca-add", description="Add CA")
public class CaAddCommand extends CaCommand
{
    @Option(name = "-name",
            required = true, description = "Required. CA name")
    protected String            caName;

    @Option(name = "-status",
            description = "CA status, active|pending|deactivated, default is active")
    protected String            caStatus;

    @Option(name = "-ocspUri",
            description = "OCSP URI, multi options is allowed",
            multiValued = true)
    protected List<String> ocspUris;

    @Option(name = "-crlUri",
            description = "CRL URI, multi options is allowed",
            multiValued = true)
    protected List<String> crlUris;

    @Option(name = "-permission",
            description = "Required. Permission, multi options is allowed. allowed values are\n" + permissionsText,
            required = true, multiValued = true)
    protected Set<String> permissions;

    @Option(name = "-nextSerial",
            description = "Required. Serial number for the next certificate, 0 for random serial number",
            required = true)
    protected Long            nextSerial;

    @Option(name = "-maxValidity",
            description = "Required. maximal validity in days",
            required = true)
    protected Integer            maxValidity;

    @Option(name = "-crlSigner",
            description = "CRL signer name")
    protected String            crlSignerName;

    @Option(name = "-numCrls",
            description = "Number of CRLs to be kept in database")
    protected Integer           numCrls;

    @Option(name = "-expirationPeriod",
            description = "Days before expiration time of CA to issue certificates\n"
                    + "the default is 365")
    protected Integer           expirationPeriod;

    @Option(name = "-cert",
            description = "CA certificate file")
    protected String            certFile;

    @Option(name = "-signerType",
            description = "Required. CA signer type",
            required = true)
    protected String            signerType;

    @Option(name = "-signerConf",
            description = "CA signer configuration")
    protected String            signerConf;

    @Option(name = "-edk", aliases = { "--enableDuplicateKey" },
            description = "Allow duplicate key, the default is not allowed")
    protected Boolean           enableDuplicateKey;

    @Option(name = "-ddk", aliases = { "--disableDuplicateKey" },
            description = "Duplicate key is not allowed")
    protected Boolean           disableDuplicateKey;

    @Option(name = "-eds", aliases = { "--enableDuplicateSubject" },
            description = "Allow duplicate subject, the default is not allowed")
    protected Boolean           enableDuplicateSubject;

    @Option(name = "-dds", aliases = { "--disableDuplicateSubject" },
            description = "Duplicate subject is not allowed")
    protected Boolean           disableDuplicateSubject;

    private SecurityFactory securityFactory;
    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(nextSerial < 0)
        {
            System.err.println("invalid serial number: " + nextSerial);
            return null;
        }

        if(numCrls == null)
        {
            numCrls = 30;
        }
        else if(numCrls < 0)
        {
            System.err.println("invalid numCrls: " + numCrls);
            return null;
        }

        if(expirationPeriod == null)
        {
            expirationPeriod = 365;
        }
        else if(expirationPeriod < 0)
        {
            System.err.println("invalid expirationPeriod: " + expirationPeriod);
            return null;
        }

        CAStatus status = CAStatus.ACTIVE;
        if(caStatus != null)
        {
            status = CAStatus.getCAStatus(caStatus);
            if(status == null)
            {
                System.out.println("invalid status: " + caStatus);
                return null;
            }
        }

        X509Certificate caCert = null;
        if(certFile != null)
        {
            caCert = IoCertUtil.parseCert(certFile);
        }

        if("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType))
        {
            signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf, passwordResolver);
        }

        // check whether the signer and certificate match
        ConcurrentContentSigner signer = securityFactory.createSigner(signerType, signerConf, caCert, passwordResolver);
        // retrieve the certificate from the key token if not specified explicitly
        if(caCert == null)
        {
            caCert = signer.getCertificate();
        }

        CAEntry entry = new CAEntry(caName, nextSerial, signerType, signerConf, caCert,
                ocspUris, crlUris, null, numCrls.intValue(), expirationPeriod.intValue());
        boolean allowDuplicateKey = isEnabled(enableDuplicateKey, disableDuplicateKey, false);
        entry.setAllowDuplicateKey(allowDuplicateKey);

        boolean allowDuplicateSubject = isEnabled(enableDuplicateSubject, disableDuplicateSubject, false);
        entry.setAllowDuplicateSubject(allowDuplicateSubject);

        entry.setStatus(status);
        if(crlSignerName != null)
        {
            entry.setCrlSignerName(crlSignerName);
        }
        entry.setMaxValidity(maxValidity);

        Set<Permission> _permissions = new HashSet<Permission>();
        for(String permission : permissions)
        {
            Permission _permission = Permission.getPermission(permission);
            if(_permission == null)
            {
                throw new ConfigurationException("Invalid permission: " + permission);
            }
            _permissions.add(_permission);
        }

        entry.setPermissions(_permissions);

        caManager.addCA(entry);

        return null;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }
}
