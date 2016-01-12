/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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

package org.xipki.pki.ca.client.shell.loadtest;

import java.security.cert.X509Certificate;
import java.util.HashMap;
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
import org.xipki.common.LoadExecutor;
import org.xipki.common.util.ParamUtil;
import org.xipki.pki.ca.client.api.CAClient;
import org.xipki.pki.ca.client.api.CAClientException;
import org.xipki.pki.ca.client.api.CertOrError;
import org.xipki.pki.ca.client.api.EnrollCertResult;
import org.xipki.pki.ca.client.api.PKIErrorException;
import org.xipki.pki.ca.client.api.dto.EnrollCertRequestEntryType;
import org.xipki.pki.ca.client.api.dto.EnrollCertRequestType;
import org.xipki.pki.ca.client.api.dto.EnrollCertRequestType.Type;

/**
 * @author Lijun Liao
 */

public class CALoadTestEnroll extends LoadExecutor {

    class Testor implements Runnable {
        @Override
        public void run() {
            while (!stop() && getErrorAccout() < 1) {
                Map<Integer, CertRequest> certReqs = nextCertRequests();
                if (certReqs != null) {
                    boolean successful = testNext(certReqs);
                    int numFailed = successful
                            ? 0
                            : 1;
                    account(1, numFailed);
                } else {
                    account(1, 1);
                }
            }
        }

        private boolean testNext(
                final Map<Integer, CertRequest> certRequests) {
            EnrollCertResult result;
            try {
                EnrollCertRequestType request = new EnrollCertRequestType(Type.CERT_REQ);
                for (Integer certId : certRequests.keySet()) {
                    String id = "id-" + certId;
                    EnrollCertRequestEntryType requestEntry = new EnrollCertRequestEntryType(
                            id,
                            loadtestEntry.getCertprofile(),
                            certRequests.get(certId),
                            RA_VERIFIED);

                    request.addRequestEntry(requestEntry);
                }

                result = caClient.requestCerts(request, null,
                        userPrefix + System.currentTimeMillis(), null);
            } catch (CAClientException | PKIErrorException e) {
                LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
                return false;
            } catch (Throwable t) {
                LOG.warn("{}: {}", t.getClass().getName(), t.getMessage());
                return false;
            }

            if (result == null) {
                return false;
            }

            Set<String> ids = result.getAllIds();
            int nSuccess = 0;
            for (String id : ids) {
                CertOrError certOrError = result.getCertificateOrError(id);
                X509Certificate cert = (X509Certificate) certOrError.getCertificate();

                if (cert != null) {
                    nSuccess++;
                }
            }

            return nSuccess == certRequests.size();
        }
    } // class Testor

    private static final ProofOfPossession RA_VERIFIED = new ProofOfPossession();

    private static final Logger LOG = LoggerFactory.getLogger(CALoadTestEnroll.class);

    private final CAClient caClient;

    private final LoadTestEntry loadtestEntry;

    private final AtomicLong index;

    private final String userPrefix = "LOADTEST-";

    private final int n;

    @Override
    protected Runnable getTestor()
    throws Exception {
        return new Testor();
    }

    public CALoadTestEnroll(
            final CAClient caClient,
            final LoadTestEntry loadtestEntry,
            final int n,
            final String description) {
        super(description);
        ParamUtil.assertNotNull("caClient", caClient);
        ParamUtil.assertNotNull("loadtestEntry", loadtestEntry);
        if (n < 1) {
            throw new IllegalArgumentException("non-positive n " + n + " is not allowed");
        }
        this.n = n;
        this.loadtestEntry = loadtestEntry;
        this.caClient = caClient;

        this.index = new AtomicLong(getSecureIndex());
    }

    private Map<Integer, CertRequest> nextCertRequests() {
        Map<Integer, CertRequest> certRequests = new HashMap<>();
        for (int i = 0; i < n; i++) {
            final int certId = i + 1;
            CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();

            long thisIndex = index.getAndIncrement();
            certTempBuilder.setSubject(loadtestEntry.getX500Name(thisIndex));

            SubjectPublicKeyInfo spki = loadtestEntry.getSubjectPublicKeyInfo(thisIndex);
            if (spki == null) {
                return null;
            }

            certTempBuilder.setPublicKey(spki);

            CertTemplate certTemplate = certTempBuilder.build();
            CertRequest certRequest = new CertRequest(certId, certTemplate, null);
            certRequests.put(certId, certRequest);
        }
        return certRequests;
    }

}
