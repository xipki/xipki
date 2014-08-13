/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.server.mgmt.CAEntry;
import org.xipki.ca.server.mgmt.DuplicationMode;
import org.xipki.ca.server.mgmt.Permission;
import org.xipki.ca.server.mgmt.ValidityMode;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.common.ConfigurationException;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "ca-add", description="Add CA")
public class CaAddCommand extends CaAddOrGenCommand
{
    @Option(name = "-cert",
            description = "CA certificate file")
    protected String certFile;

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
                ocspUris, crlUris, deltaCrlUris, null, numCrls.intValue(), expirationPeriod.intValue());

        DuplicationMode duplicateKey = getDuplicationMode(duplicateKeyI, DuplicationMode.FORBIDDEN_WITHIN_PROFILE);
        entry.setDuplicateKeyMode(duplicateKey);

        DuplicationMode duplicateSubject = getDuplicationMode(duplicateSubjectI, DuplicationMode.FORBIDDEN_WITHIN_PROFILE);
        entry.setDuplicateSubjectMode(duplicateSubject);

        ValidityMode validityMode = null;
        if(validityModeS != null)
        {
            validityMode = ValidityMode.getInstance(validityModeS);
        }
        if(validityMode == null)
        {
            validityMode = ValidityMode.STRICT;
        }
        entry.setValidityMode(validityMode);

        entry.setStatus(status);
        if(crlSignerName != null)
        {
            entry.setCrlSignerName(crlSignerName);
        }
        entry.setMaxValidity(maxValidity);

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

        entry.setPermissions(_permissions);

        caManager.addCA(entry);

        return null;
    }
}
