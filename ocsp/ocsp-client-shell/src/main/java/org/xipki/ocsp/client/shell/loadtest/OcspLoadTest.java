/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.client.shell.loadtest;

import java.math.BigInteger;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.OCSPRequestorException;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.security.common.AbstractLoadTest;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class OcspLoadTest extends AbstractLoadTest
{
    private static final Logger LOG = LoggerFactory.getLogger(OcspLoadTest.class);

    private final OCSPRequestor requestor;
    private final List<Long> serials;
    private final int numSerials;
    private int serialIndex;

    private X509Certificate caCert;
    private URL serverUrl;
    private RequestOptions options;

    @Override
    protected Runnable getTestor()
    throws Exception
    {
        return new Testor();
    }

    public OcspLoadTest(OCSPRequestor requestor, List<Long> serials,
            X509Certificate caCert, URL serverUrl, RequestOptions options)
    {
        ParamChecker.assertNotNull("requestor", requestor);
        ParamChecker.assertNotEmpty("serials", serials);
        ParamChecker.assertNotNull("caCert", caCert);
        ParamChecker.assertNotNull("serverUrl", serverUrl);
        ParamChecker.assertNotNull("options", options);

        this.requestor = requestor;
        this.serials = serials;
        this.numSerials = serials.size();
        this.caCert = caCert;
        this.serverUrl = serverUrl;
        this.options = options;

        this.serialIndex = 0;
    }

    private synchronized long nextSerialNumber()
    {
        serialIndex++;
        if(serialIndex >= numSerials)
        {
            serialIndex = 0;
        }
        return this.serials.get(serialIndex);
    }

    class Testor implements Runnable
    {

        @Override
        public void run()
        {
            while(stop() == false && getErrorAccout() < 10)
            {
                long sn = nextSerialNumber();
                account(1, (testNext(sn)? 0: 1));
            }
        }

        private boolean testNext(long sn)
        {
            BasicOCSPResp basicResp;
            try
            {
                basicResp = requestor.ask(caCert, BigInteger.valueOf(sn), serverUrl, options);
            } catch (OCSPRequestorException e)
            {
                LOG.warn("OCSPRequestorException: {}", e.getMessage());
                return false;
            }

            SingleResp[] singleResponses = basicResp.getResponses();

            int n = singleResponses == null ? 0 : singleResponses.length;
            if(n == 0)
            {
                LOG.warn("Received no status from server");
                return false;
            }
            else if(n != 1)
            {
                LOG.warn("Received status with {} single responses from server, but 1 was requested", n);
                return false;
            }
            else
            {
                SingleResp singleResp = singleResponses[0];
                CertificateStatus singleCertStatus = singleResp.getCertStatus();

                String status ;
                if(singleCertStatus == null)
                {
                    status = "Good";
                }
                else if(singleCertStatus instanceof RevokedStatus)
                {
                    RevokedStatus revStatus = (RevokedStatus) singleCertStatus;
                    Date revTime = revStatus.getRevocationTime();

                    if(revStatus.hasRevocationReason())
                    {
                        int reason = revStatus.getRevocationReason();
                        status = "Revoked, reason = "+ reason + ", revocationTime = " + revTime;
                    }
                    else
                    {
                        status = "Revoked, no reason, revocationTime = " + revTime;
                    }
                }
                else if(singleCertStatus instanceof UnknownStatus)
                {
                    status = "Unknown";
                }
                else
                {
                    LOG.warn("Status: ERROR");
                    return false;
                }

                LOG.info("SN: {}, Status: {}", sn, status);
                return true;
            }
        }

    }

}
