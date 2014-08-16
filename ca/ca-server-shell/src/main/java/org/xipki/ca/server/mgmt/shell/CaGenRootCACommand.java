/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.server.RandomSerialNumberGenerator;
import org.xipki.ca.server.mgmt.api.CAEntry;
import org.xipki.ca.server.mgmt.api.CertProfileEntry;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.IdentifiedCertProfile;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.shell.SelfSignedCertBuilder.GenerateSelfSignedResult;
import org.xipki.security.common.ConfigurationException;

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

        CertProfileEntry certProfileEntry = caManager.getCertProfile(rcaProfile);
        if(certProfileEntry == null)
        {
            throw new OperationException(ErrorCode.UNKNOWN_CERT_PROFILE,
                    "unknown cert profile " + rcaProfile);
        }

        long serialOfThisCert;
        if(nextSerial > 0)
        {
            serialOfThisCert = nextSerial;
            nextSerial ++;
        }
        else
        {
            serialOfThisCert = RandomSerialNumberGenerator.getInstance().getSerialNumber().longValue();
        }

        IdentifiedCertProfile certProfile = certProfileEntry.getCertProfile();
        GenerateSelfSignedResult result = SelfSignedCertBuilder.generateSelfSigned(
                securityFactory, passwordResolver, signerType, signerConf,
                certProfile, rcaSubject, serialOfThisCert, ocspUris, crlUris);

        signerConf = result.getSignerConf();
        X509Certificate caCert = result.getCert();

        if("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType))
        {
            signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf, passwordResolver);
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

        if(rcaCertOutFile != null)
        {
            saveVerbose("Saved root certificate to file", new File(rcaCertOutFile), caCert.getEncoded());
        }

        return null;
    }

}
