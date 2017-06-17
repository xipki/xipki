/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.LoadExecutor;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.pki.ca.client.api.CaClient;
import org.xipki.pki.ca.client.api.CaClientException;
import org.xipki.pki.ca.client.api.CertIdOrError;
import org.xipki.pki.ca.client.api.PkiErrorException;
import org.xipki.pki.ca.client.api.dto.RevokeCertRequest;
import org.xipki.pki.ca.client.api.dto.RevokeCertRequestEntry;
import org.xipki.security.CrlReason;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaLoadTestRevoke extends LoadExecutor {

    private static final Logger LOG = LoggerFactory.getLogger(CaLoadTestRevoke.class);

    private static final CrlReason[] REASONS = {CrlReason.UNSPECIFIED, CrlReason.KEY_COMPROMISE,
        CrlReason.AFFILIATION_CHANGED, CrlReason.SUPERSEDED, CrlReason.CESSATION_OF_OPERATION,
        CrlReason.CERTIFICATE_HOLD, CrlReason.PRIVILEGE_WITHDRAWN};

    private final CaClient caClient;

    private final X500Name caSubject;

    private final int num;

    private final int maxCerts;

    private final Iterator<BigInteger> serialNumberIterator;

    private AtomicInteger processedCerts = new AtomicInteger(0);

    public CaLoadTestRevoke(final CaClient caClient, final Certificate caCert,
            final Iterator<BigInteger> serialNumberIterator, final int maxCerts, final int num,
            final String description) throws Exception {
        super(description);
        ParamUtil.requireNonNull("caCert", caCert);
        this.num = ParamUtil.requireMin("num", num, 1);
        this.caClient = ParamUtil.requireNonNull("caClient", caClient);
        this.serialNumberIterator = ParamUtil.requireNonNull("serialNumberIterator",
                serialNumberIterator);
        this.caSubject = caCert.getSubject();
        this.maxCerts = maxCerts;
    } // constructor

    class Testor implements Runnable {

        @Override
        public void run() {
            while (!stop() && getErrorAccout() < 1) {
                List<BigInteger> serialNumbers;
                try {
                    serialNumbers = nextSerials();
                } catch (DataAccessException ex) {
                    account(1, 1);
                    break;
                }

                if (CollectionUtil.isEmpty(serialNumbers)) {
                    break;
                }

                boolean successful = testNext(serialNumbers);
                int numFailed = successful ? 0 : 1;
                account(1, numFailed);
            }
        }

        private boolean testNext(final List<BigInteger> serialNumbers) {
            RevokeCertRequest request = new RevokeCertRequest();
            int id = 1;
            for (BigInteger serialNumber : serialNumbers) {
                CrlReason reason = REASONS[Math.abs(serialNumber.intValue()) % REASONS.length];
                RevokeCertRequestEntry entry = new RevokeCertRequestEntry(Integer.toString(id++),
                        caSubject, serialNumber, reason.code(), null);
                request.addRequestEntry(entry);
            }

            Map<String, CertIdOrError> result;
            try {
                result = caClient.revokeCerts(request, null);
            } catch (CaClientException | PkiErrorException ex) {
                LOG.warn("{}: {}", ex.getClass().getName(), ex.getMessage());
                return false;
            } catch (Throwable th) {
                LOG.warn("{}: {}", th.getClass().getName(), th.getMessage());
                return false;
            }

            if (result == null) {
                return false;
            }

            int numSuccess = 0;
            for (CertIdOrError entry : result.values()) {
                if (entry.certId() != null) {
                    numSuccess++;
                }
            }
            return numSuccess == serialNumbers.size();
        } // method testNext

    } // class Testor

    @Override
    protected Runnable getTestor() throws Exception {
        return new Testor();
    }

    private List<BigInteger> nextSerials() throws DataAccessException {
        List<BigInteger> ret = new ArrayList<>(num);
        for (int i = 0; i < num; i++) {
            if (maxCerts > 0) {
                int num = processedCerts.getAndAdd(1);
                if (num >= maxCerts) {
                    break;
                }
            }

            if (serialNumberIterator.hasNext()) {
                BigInteger serial = serialNumberIterator.next();
                ret.add(serial);
            } else {
                break;
            }
        }
        return ret;
    }

}
