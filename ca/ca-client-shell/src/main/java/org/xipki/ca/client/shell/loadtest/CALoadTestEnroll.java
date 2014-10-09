/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell.loadtest;

import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.client.api.RAWorker;
import org.xipki.ca.cmp.client.type.EnrollCertRequestEntryType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestType.Type;
import org.xipki.ca.common.CertificateOrError;
import org.xipki.ca.common.EnrollCertResult;
import org.xipki.ca.common.PKIErrorException;
import org.xipki.ca.common.RAWorkerException;
import org.xipki.security.common.AbstractLoadTest;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class CALoadTestEnroll extends AbstractLoadTest
{
    private static final ProofOfPossession RA_VERIFIED = new ProofOfPossession();

    private static final Logger LOG = LoggerFactory.getLogger(CALoadTestEnroll.class);

    private final RAWorker raWorker;
    private final LoadTestEntry loadtestEntry;
    private final String user;
    private AtomicLong index;
    private final int n;

    @Override
    protected Runnable getTestor()
    throws Exception
    {
        return new Testor();
    }

    public CALoadTestEnroll(RAWorker raWorker, LoadTestEntry loadtestEntry,
            String user, int n)
    {
        ParamChecker.assertNotNull("raWorker", raWorker);
        ParamChecker.assertNotNull("loadtestEntry", loadtestEntry);
        if(n < 1)
        {
            throw new IllegalArgumentException("non-positive n " + n + " is not allowed");
        }
        this.n = n;
        this.loadtestEntry = loadtestEntry;
        this.user = user == null ? "LOADTESTER" : user;
        this.raWorker = raWorker;

        Calendar baseTime = Calendar.getInstance(Locale.UK);
        baseTime.set(Calendar.YEAR, 2014);
        baseTime.set(Calendar.MONTH, 0);
        baseTime.set(Calendar.DAY_OF_MONTH, 1);

        this.index = new AtomicLong((System.currentTimeMillis() - baseTime.getTimeInMillis()) * 10);
    }

    private Map<Integer, CertRequest> nextCertRequests()
    {
        Map<Integer, CertRequest> certRequests = new HashMap<>();
        for(int i = 0; i < n; i++)
        {
            final int certId = i + 1;
            CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();

            long thisIndex = index.getAndIncrement();
            certTempBuilder.setSubject(loadtestEntry.getX500Name(thisIndex));

            SubjectPublicKeyInfo spki = loadtestEntry.getSubjectPublicKeyInfo(thisIndex);
            if(spki == null)
            {
                return null;
            }

            certTempBuilder.setPublicKey(spki);

            CertTemplate certTemplate = certTempBuilder.build();
            CertRequest certRequest = new CertRequest(certId, certTemplate, null);
            certRequests.put(certId, certRequest);
        }
        return certRequests;
    }

    class Testor implements Runnable
    {

        @Override
        public void run()
        {
            while(stop() == false && getErrorAccout() < 1)
            {
                Map<Integer, CertRequest> certReqs = nextCertRequests();
                if(certReqs != null)
                {
                    int size = certReqs.size();
                    int nSucc = testNext(certReqs);
                    int failed = size - nSucc;
                    if(failed < 0)
                    {
                        failed = size;
                    }
                    account(size, failed);
                }
                else
                {
                    account(1, 1);
                }
            }
        }

        private int testNext(Map<Integer, CertRequest> certRequests)
        {
            EnrollCertResult result;
            try
            {
                EnrollCertRequestType request = new EnrollCertRequestType(Type.CERT_REQ);
                for(Integer certId : certRequests.keySet())
                {
                    String id = "id-" + certId;
                    EnrollCertRequestEntryType requestEntry = new EnrollCertRequestEntryType
                            (id, loadtestEntry.getCertProfile(), certRequests.get(certId), RA_VERIFIED);

                    request.addRequestEntry(requestEntry);
                }

                result = raWorker.requestCerts(request, null, user);
            } catch (RAWorkerException | PKIErrorException e)
            {
                LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
                return 0;
            } catch (Throwable t)
            {
                LOG.warn("{}: {}", t.getClass().getName(), t.getMessage());
                return 0;
            }

            if(result == null)
            {
                return 0;
            }

            Set<String> ids = result.getAllIds();
            int nSuccess = 0;
            for(String id : ids)
            {
                CertificateOrError certOrError = result.getCertificateOrError(id);
                X509Certificate cert = (X509Certificate) certOrError.getCertificate();

                if(cert != null)
                {
                    nSuccess++;
                }
            }

            return nSuccess;
        }

    }
}
