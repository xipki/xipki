/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
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
import org.xipki.ca.common.CAStatus;
import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.common.ConfigurationException;
import org.xipki.common.IoCertUtil;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "ca-update", description="Update CA")
public class CaUpdateCommand extends CaCommand
{
    @Option(name = "-name",
            required = true, description = "Required. CA name")
    protected String caName;

    @Option(name = "-status",
            description = "CA status, active|pending|deactivated")
    protected String caStatus;

    @Option(name = "-ocspUri",
            description = "OCSP URI or 'NULL', multi options is allowed",
            multiValued = true)
    protected List<String> ocspUris;

    @Option(name = "-crlUri",
            description = "CRL URI or 'NULL', multi options is allowed",
            multiValued = true)
    protected List<String> crlUris;

    @Option(name = "-deltaCrlUri",
            description = "Delta CRL URI or 'NULL', multi options is allowed",
            multiValued = true)
    protected List<String> deltaCrlUris;

    @Option(name = "-permission",
            description = "Permission, multi options is allowed. allowed values are\n" + permissionsText,
            multiValued = true)
    protected Set<String> permissions;

    @Option(name = "-maxValidity",
            description = "Maximal validity in days")
    protected Integer maxValidity;

    @Option(name = "-expirationPeriod",
            description = "Days before expiration time of CA to issue certificates")
    protected Integer expirationPeriod;

    @Option(name = "-crlSigner",
            description = "CRL signer name or 'NULL'")
    protected String crlSignerName;

    @Option(name = "-numCrls",
            description = "Number of CRLs to be kept in database")
    protected Integer numCrls;

    @Option(name = "-cert",
            description = "CA certificate file")
    protected String certFile;

    @Option(name = "-signerType",
            description = "CA signer type")
    protected String signerType;

    @Option(name = "-signerConf",
            description = "CA signer configuration or 'NULL'")
    protected String signerConf;

    @Option(name = "-dk", aliases = { "--duplicateKey" },
            description = "Mode of duplicate key.\n"
                    + "\t1: forbidden\n"
                    + "\t2: forbiddenWithinProfile\n"
                    + "\t3: allowed")
    protected String duplicateKeyS;

    @Option(name = "-ds", aliases = { "--duplicateSubject" },
            description = "Mode of duplicate subject.\n"
                    + "\t1: forbidden\n"
                    + "\t2: forbiddenWithinProfile\n"
                    + "\t3: allowed")
    protected String duplicateSubjectS;

    @Option(name = "-validityMode",
            description = "Mode of valditity.\n"
                    + "\tSTRICT: Reject if the notBefore + validity behinds CA's notAfter \n"
                    + "\tLAX:    notBefore + validity after CA's notAfter is permitted\n"
                    + "\tCUTOFF: notAfter of issued certificates will be set to the earlier time of\n"
                    + "\t        notBefore + validigty and CA's notAfter")
    protected String validityModeS;

    protected SecurityFactory securityFactory;

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    @Override
    protected Object doExecute()
    throws Exception
    {
        CAStatus status = null;
        if(caStatus != null)
        {
            status = CAStatus.getCAStatus(caStatus);
        }

        if(expirationPeriod != null && expirationPeriod < 0)
        {
            err("invalid expirationPeriod: " + expirationPeriod);
            return null;
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
                signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf, securityFactory.getPasswordResolver());
            }
        }

        DuplicationMode duplicateKey = null;
        if(duplicateKeyS != null)
        {
            duplicateKey = DuplicationMode.getInstance(duplicateKeyS);
            if(duplicateKey == null)
            {
                err("invalid duplication mode " + duplicateKeyS);
            }
        }

        DuplicationMode duplicateSubject = null;
        if(duplicateSubjectS != null)
        {
            duplicateSubject = DuplicationMode.getInstance(duplicateSubjectS);
            if(duplicateKey == null)
            {
                err("invalid duplication mode " + duplicateSubjectS);
            }
        }

        Set<Permission> _permissions = null;
        if (permissions != null && permissions.size() > 0)
        {
            _permissions = new HashSet<>();
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
                _crlUris = new HashSet<>(crlUris);
            }
        }

        boolean clearDeltaCrlUris = false;
        if(deltaCrlUris != null)
        {
            for(String uri : deltaCrlUris)
            {
                if(CAManager.NULL.equalsIgnoreCase(uri))
                {
                    clearDeltaCrlUris = true;
                    break;
                }
            }
        }

        Set<String> _deltaCrlUris = null;

        if(clearDeltaCrlUris)
        {
            _deltaCrlUris = Collections.emptySet();
        }
        else
        {
            if(deltaCrlUris != null )
            {
                _deltaCrlUris = new HashSet<>(deltaCrlUris);
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
                _ocspUris = new HashSet<>(ocspUris);
            }
        }

        ValidityMode validityMode = null;
        if(validityModeS != null)
        {
            validityMode = ValidityMode.getInstance(validityModeS);
            if(validityMode == null)
            {
                throw new ConfigurationException("Invalid validity mode: " + validityModeS);
            }
        }

        caManager.changeCA(
                caName,
                status,
                caCert,
                _crlUris,
                _deltaCrlUris,
                _ocspUris,
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

        out("updated CA " + caName);
        return null;
    }
}
