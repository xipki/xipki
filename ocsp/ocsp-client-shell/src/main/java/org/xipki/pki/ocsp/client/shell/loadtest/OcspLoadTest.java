/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ocsp.client.shell.loadtest;

import java.math.BigInteger;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.LoadExecutor;
import org.xipki.common.util.ParamUtil;
import org.xipki.pki.ocsp.client.api.OCSPRequestor;
import org.xipki.pki.ocsp.client.api.OCSPRequestorException;
import org.xipki.pki.ocsp.client.api.OCSPResponseException;
import org.xipki.pki.ocsp.client.api.RequestOptions;
import org.xipki.pki.ocsp.client.shell.OCSPUtils;

/**
 * @author Lijun Liao
 */

public class OcspLoadTest extends LoadExecutor
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

    public OcspLoadTest(
            final OCSPRequestor requestor,
            final List<Long> serials,
            final X509Certificate caCert,
            final URL serverUrl,
            final RequestOptions options,
            final String description)
    {
        super(description);
        ParamUtil.assertNotNull("requestor", requestor);
        ParamUtil.assertNotEmpty("serials", serials);
        ParamUtil.assertNotNull("caCert", caCert);
        ParamUtil.assertNotNull("serverUrl", serverUrl);
        ParamUtil.assertNotNull("options", options);

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
                int numFailed = testNext(sn)
                        ? 0
                        : 1;

                account(1, numFailed);
            }
        }

        private boolean testNext(
                final long sn)
        {
            BasicOCSPResp basicResp;
            try
            {
                OCSPResp response = requestor.ask(caCert, BigInteger.valueOf(sn), serverUrl, options, null);
                basicResp = OCSPUtils.extractBasicOCSPResp(response);
            } catch (OCSPRequestorException e)
            {
                LOG.warn("OCSPRequestorException: {}", e.getMessage());
                return false;
            } catch (OCSPResponseException e)
            {
                LOG.warn("OCSPResponseException: {}", e.getMessage());
                return false;
            } catch (Throwable t)
            {
                LOG.warn("{}: {}", t.getClass().getName(), t.getMessage());
                return false;
            }

            SingleResp[] singleResponses = basicResp.getResponses();

            int n = (singleResponses == null)
                    ? 0
                    : singleResponses.length;

            if(n == 0)
            {
                LOG.warn("received no status from server");
                return false;
            }
            else if(n != 1)
            {
                LOG.warn("received status with {} single responses from server, but 1 was requested", n);
                return false;
            }
            else
            {
                SingleResp singleResp = singleResponses[0];
                CertificateStatus singleCertStatus = singleResp.getCertStatus();

                String status ;
                if(singleCertStatus == null)
                {
                    status = "good";
                }
                else if(singleCertStatus instanceof RevokedStatus)
                {
                    RevokedStatus revStatus = (RevokedStatus) singleCertStatus;
                    Date revTime = revStatus.getRevocationTime();

                    if(revStatus.hasRevocationReason())
                    {
                        int reason = revStatus.getRevocationReason();
                        status = "revoked, reason = "+ reason + ", revocationTime = " + revTime;
                    }
                    else
                    {
                        status = "revoked, no reason, revocationTime = " + revTime;
                    }
                }
                else if(singleCertStatus instanceof UnknownStatus)
                {
                    status = "unknown";
                }
                else
                {
                    LOG.warn("status: ERROR");
                    return false;
                }

                LOG.info("SN: {}, status: {}", sn, status);
                return true;
            }
        }

    }

}
