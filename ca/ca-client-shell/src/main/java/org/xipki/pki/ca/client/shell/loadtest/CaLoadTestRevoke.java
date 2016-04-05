/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.LoadExecutor;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;
import org.xipki.commons.security.api.CrlReason;
import org.xipki.commons.security.api.HashAlgoType;
import org.xipki.pki.ca.client.api.CaClient;
import org.xipki.pki.ca.client.api.CaClientException;
import org.xipki.pki.ca.client.api.CertIdOrError;
import org.xipki.pki.ca.client.api.PkiErrorException;
import org.xipki.pki.ca.client.api.dto.RevokeCertRequestEntryType;
import org.xipki.pki.ca.client.api.dto.RevokeCertRequestType;

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

    private final DataSourceWrapper caDataSource;

    private final X500Name caSubject;

    private final Set<Long> excludeSerials = new HashSet<>();

    private final ConcurrentLinkedDeque<Long> serials = new ConcurrentLinkedDeque<>();

    private final int caInfoId;

    private final long minSerial;

    private final long maxSerial;

    private final int maxCerts;

    private final int num;

    private AtomicInteger processedCerts = new AtomicInteger(0);

    private long nextStartSerial;

    private boolean noUnrevokedCerts;

    public CaLoadTestRevoke(
            final CaClient caClient,
            final Certificate caCert,
            final DataSourceWrapper caDataSource,
            final int maxCerts,
            final int num,
            final String description)
    throws Exception {
        super(description);
        ParamUtil.requireNonNull("caCert", caCert);
        this.num = ParamUtil.requireMin("num", num, 1);
        this.caClient = ParamUtil.requireNonNull("caClient", caClient);
        this.caDataSource = ParamUtil.requireNonNull("caDataSource", caDataSource);
        this.caSubject = caCert.getSubject();
        this.maxCerts = maxCerts;

        if (caCert.getIssuer().equals(caCert.getSubject())) {
            this.excludeSerials.add(caCert.getSerialNumber().getPositiveValue().longValue());
        }

        String b64Sha1Fp = HashAlgoType.SHA1.base64Hash(caCert.getEncoded());
        String sql = "SELECT ID FROM CS_CA WHERE SHA1_CERT='" + b64Sha1Fp + "'";
        Statement stmt = caDataSource.getConnection().createStatement();
        try {
            ResultSet rs = stmt.executeQuery(sql);
            if (rs.next()) {
                caInfoId = rs.getInt("ID");
            } else {
                throw new Exception("CA Certificate and database configuration does not match");
            }
            rs.close();

            sql = "SELECT MIN(SN) FROM CERT WHERE REV=0 AND CA_ID=" + caInfoId;
            rs = stmt.executeQuery(sql);
            rs.next();
            minSerial = rs.getLong(1);
            nextStartSerial = minSerial;

            sql = "SELECT MAX(SN) FROM CERT WHERE REV=0 AND CA_ID=" + caInfoId;
            rs = stmt.executeQuery(sql);
            rs.next();
            maxSerial = rs.getLong(1);
        } finally {
            caDataSource.releaseResources(stmt, null);
        }
    } // constructor

    class Testor implements Runnable {

        @Override
        public void run() {
            while (!stop() && getErrorAccout() < 1) {
                List<Long> serialNumbers;
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
                int numFailed = successful
                        ? 0
                        : 1;
                account(1, numFailed);
            }
        }

        private boolean testNext(
                final List<Long> serialNumbers) {
            RevokeCertRequestType request = new RevokeCertRequestType();
            int id = 1;
            for (Long serialNumber : serialNumbers) {
                CrlReason reason = REASONS[(int) (serialNumber % REASONS.length)];
                RevokeCertRequestEntryType entry = new RevokeCertRequestEntryType(
                        Integer.toString(id++), caSubject, BigInteger.valueOf(serialNumber),
                        reason.getCode(), null);
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
                if (entry.getCertId() != null) {
                    numSuccess++;
                }
            }
            return numSuccess == serialNumbers.size();
        } // method testNext

    } // class Testor

    @Override
    protected Runnable getTestor()
    throws Exception {
        return new Testor();
    }

    private List<Long> nextSerials()
    throws DataAccessException {
        List<Long> ret = new ArrayList<>(num);
        for (int i = 0; i < num; i++) {
            Long serial = nextSerial();
            if (serial != null) {
                ret.add(serial);
            } else {
                break;
            }
        }
        return ret;
    }

    private Long nextSerial()
    throws DataAccessException {
        synchronized (caDataSource) {
            if (maxCerts > 0) {
                int num = processedCerts.getAndAdd(1);
                if (num >= maxCerts) {
                    return null;
                }
            }

            Long firstSerial = serials.pollFirst();
            if (firstSerial != null) {
                return firstSerial;
            }

            if (noUnrevokedCerts) {
                return serials.pollFirst();
            }

            String sql = "SN FROM CERT WHERE REV=0 AND CA_ID=" + caInfoId
                    + " AND SN > " + (nextStartSerial - 1) + " AND SN < " + (maxSerial + 1);
            sql = caDataSource.createFetchFirstSelectSql(sql, 1000, "SN");
            PreparedStatement stmt = null;
            ResultSet rs = null;

            int idx = 0;
            try {
                stmt = caDataSource.getConnection().prepareStatement(sql);
                rs = stmt.executeQuery();
                while (rs.next()) {
                    idx++;
                    long serial = rs.getLong("SN");
                    if (serial + 1 > nextStartSerial) {
                        nextStartSerial = serial + 1;
                    }
                    if (!excludeSerials.contains(serial)) {
                        serials.addLast(serial);
                    }
                }
            } catch (SQLException ex) {
                throw caDataSource.translate(sql, ex);
            } finally {
                caDataSource.releaseResources(stmt, rs);
            }

            if (idx == 0) {
                System.out.println("no unrevoked certificate");
                System.out.flush();
            }

            if (idx < 1000) {
                noUnrevokedCerts = true;
            }

            return serials.pollFirst();
        }
    } // method nextSerial

}
