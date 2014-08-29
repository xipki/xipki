/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.cmp.client;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.cmp.client.type.EnrollCertResultEntryType;
import org.xipki.ca.cmp.client.type.EnrollCertResultType;
import org.xipki.ca.cmp.client.type.ErrorResultEntryType;
import org.xipki.ca.cmp.client.type.ErrorResultType;
import org.xipki.ca.cmp.client.type.ResultEntryType;
import org.xipki.ca.common.CertificateOrError;
import org.xipki.ca.common.EnrollCertResult;
import org.xipki.ca.common.PKIErrorException;
import org.xipki.ca.common.RAWorkerException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.LogUtil;

/**
 * @author Lijun Liao
 */

public abstract class AbstractRAWorker
{
    private static final Logger LOG = LoggerFactory.getLogger(AbstractRAWorker.class);

    protected static final ProofOfPossession raVerified = new ProofOfPossession();

    protected abstract Certificate getCertificate(CMPCertificate cmpCert)
    throws CertificateException;

    protected abstract boolean verify(Certificate caCert, Certificate cert);

    protected SecurityFactory securityFactory;

    protected AbstractRAWorker()
    {
    }

    protected EnrollCertResult parseEnrollCertResult(EnrollCertResultType result, String caName)
    throws RAWorkerException
    {
        Map<String, CertificateOrError> certOrErrors = new HashMap<>();
        for(ResultEntryType resultEntry : result.getResultEntries())
        {
            CertificateOrError certOrError;
            if(resultEntry instanceof EnrollCertResultEntryType)
            {
                EnrollCertResultEntryType entry = (EnrollCertResultEntryType) resultEntry;
                try
                {
                    Certificate cert = getCertificate(entry.getCert());
                    certOrError = new CertificateOrError(cert);
                } catch (CertificateException e)
                {
                    throw new RAWorkerException(
                            "CertificateParsingException for request (id=" + entry.getId()+"): " + e.getMessage());
                }
            }
            else if(resultEntry instanceof ErrorResultEntryType)
            {
                certOrError = new CertificateOrError(
                        ((ErrorResultEntryType) resultEntry).getStatusInfo());
            }
            else
            {
                certOrError = null;
            }

            certOrErrors.put(resultEntry.getId(), certOrError);
        }

        Certificate caCert = null;

        List<CMPCertificate> cmpCaPubs = result.getCACertificates();

        if(cmpCaPubs != null && cmpCaPubs.isEmpty() == false)
        {
            List<Certificate> caPubs = new ArrayList<>(cmpCaPubs.size());
            for(CMPCertificate cmpCaPub : cmpCaPubs)
            {
                try
                {
                    caPubs.add(getCertificate(cmpCaPub));
                } catch (CertificateException e)
                {
                    final String message = "Could not extract the caPub from CMPCertificate";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);
                }
            }

            for(CertificateOrError certOrError : certOrErrors.values())
            {
                Certificate cert = certOrError.getCertificate();
                if(cert == null)
                {
                    continue;
                }

                if(caCert == null)
                {
                    for(Certificate caPub : caPubs)
                    {
                        if(verify(caPub, cert))
                        {
                            caCert = caPub;
                        }
                    }
                }
                else if(verify(caCert, cert) == false)
                {
                    LOG.warn("Not all certificates issued by CA embedded in caPubs, ignore the caPubs");
                    caCert = null;
                    break;
                }
            }
        }

        return new EnrollCertResult(caCert, certOrErrors);
    }

    protected static PKIErrorException createPKIErrorException(ErrorResultType errResult)
    {
        return new PKIErrorException(errResult.getStatus(),
                errResult.getPkiFailureInfo(), errResult.getStatusMessage());
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

}
