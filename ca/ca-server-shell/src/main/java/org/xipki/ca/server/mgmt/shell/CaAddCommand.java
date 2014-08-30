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
import org.xipki.ca.common.CAStatus;
import org.xipki.ca.server.mgmt.api.CAEntry;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.ValidityMode;
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

        X509Certificate caCert = null;
        if(certFile != null)
        {
            caCert = IoCertUtil.parseCert(certFile);
        }

        if("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType))
        {
            signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf, securityFactory.getPasswordResolver());
        }

        // check whether the signer and certificate match
        ConcurrentContentSigner signer = securityFactory.createSigner(signerType, signerConf, caCert);
        // retrieve the certificate from the key token if not specified explicitly
        if(caCert == null)
        {
            caCert = signer.getCertificate();
        }

        CAEntry entry = new CAEntry(caName, nextSerial, signerType, signerConf, caCert,
                ocspUris, crlUris, deltaCrlUris, null, numCrls.intValue(), expirationPeriod.intValue());

        DuplicationMode duplicateKey = DuplicationMode.getInstance(duplicateKeyS);
        if(duplicateKey == null)
        {
            err("invalid duplication mode: " + duplicateKeyS);
        }
        entry.setDuplicateKeyMode(duplicateKey);

        DuplicationMode duplicateSubject = DuplicationMode.getInstance(duplicateSubjectS);
        if(duplicateSubject == null)
        {
            err("invalid duplication mode: " + duplicateSubjectS);
        }
        entry.setDuplicateSubjectMode(duplicateSubject);

        ValidityMode validityMode = ValidityMode.getInstance(validityModeS);
        if(validityMode == null)
        {
            err("invalid validity: " + validityModeS);
            return null;
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

        out("added CA " + caName);

        return null;
    }
}
