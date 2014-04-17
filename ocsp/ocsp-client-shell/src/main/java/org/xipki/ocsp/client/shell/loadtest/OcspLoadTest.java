/*
 * Copyright 2014 xipki.org
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

package org.xipki.ocsp.client.shell.loadtest;

import java.math.BigInteger;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Date;

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
import org.xipki.security.common.ParamChecker;

public class OcspLoadTest extends AbstractLoadTest
{
    private static final Logger LOG = LoggerFactory.getLogger(OcspLoadTest.class);

    private final OCSPRequestor requestor;
    private final long startSerial;
    private final long endSerial;
    private long serial;

    private X509Certificate caCert;
    private URL serverUrl;
    private RequestOptions options;

    @Override
    protected Runnable getTestor() throws Exception
    {
        return new Testor();
    }

    public OcspLoadTest(OCSPRequestor requestor, long startSerial, long endSerial,
            X509Certificate caCert, URL serverUrl, RequestOptions options)
    {
        ParamChecker.assertNotNull("requestor", requestor);
        ParamChecker.assertNotNull("caCert", caCert);
        ParamChecker.assertNotNull("serverUrl", serverUrl);
        ParamChecker.assertNotNull("options", options);

        this.requestor = requestor;
        this.startSerial = startSerial;
        this.endSerial = endSerial;
        this.caCert = caCert;
        this.serverUrl = serverUrl;
        this.options = options;

        this.serial = this.endSerial;
    }

    private synchronized long nextSerialNumber()
    {
        serial++;
        if(serial > endSerial)
        {
            serial = startSerial;
        }
        return serial;
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
                basicResp = requestor.ask(caCert, BigInteger.valueOf(serial++), serverUrl, options);
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
                    int reason = ((RevokedStatus) singleCertStatus).getRevocationReason();
                    Date revTime = ((RevokedStatus) singleCertStatus).getRevocationTime();
                    status = "Revocated, reason = "+ reason + ", revocationTime = " + revTime;
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

    } // End class OcspRequestor

}
