/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell.loadtest;

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
import org.xipki.ca.client.api.RAWorker;
import org.xipki.ca.cmp.client.type.RevokeCertRequestEntryType;
import org.xipki.ca.cmp.client.type.RevokeCertRequestType;
import org.xipki.ca.common.CertIDOrError;
import org.xipki.ca.common.PKIErrorException;
import org.xipki.ca.common.RAWorkerException;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.security.common.AbstractLoadTest;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class CALoadTestRevoke extends AbstractLoadTest
{
    private static final Logger LOG = LoggerFactory.getLogger(CALoadTestRevoke.class);

    private final RAWorker raWorker;
    private final DataSourceWrapper caDataSource;
    private final X500Name caSubject;
    private final Set<Long> excludeSerials = new HashSet<>();
    private final ConcurrentLinkedDeque<Long> serials = new ConcurrentLinkedDeque<>();
    private final int caInfoId;
    private final long minSerial;
    private final long maxSerial;
    private final int maxCerts;
    private final int n;

    private AtomicInteger processedCerts = new AtomicInteger(0);

    private long nextStartSerial;
    private boolean noUnrevokedCerts = false;

    private CRLReason[] reasons =
        { CRLReason.UNSPECIFIED, CRLReason.KEY_COMPROMISE,
            CRLReason.AFFILIATION_CHANGED, CRLReason.SUPERSEDED, CRLReason.CESSATION_OF_OPERATION,
            CRLReason.CERTIFICATE_HOLD,    CRLReason.PRIVILEGE_WITHDRAWN};

    @Override
    protected Runnable getTestor()
    throws Exception
    {
        return new Testor();
    }

    public CALoadTestRevoke(RAWorker raWorker, Certificate caCert,
            DataSourceWrapper caDataSource, int maxCerts, int n)
    throws Exception
    {
        ParamChecker.assertNotNull("raWorker", raWorker);
        ParamChecker.assertNotNull("caCert", caCert);
        ParamChecker.assertNotNull("caDataSource", caDataSource);
        if(n < 1)
        {
            throw new IllegalArgumentException("non-positive n " + n + " is not allowed");
        }
        this.n = n;

        this.raWorker = raWorker;
        this.caDataSource = caDataSource;
        this.caSubject = caCert.getSubject();
        this.maxCerts = maxCerts;
        if(caCert.getIssuer().equals(caCert.getSubject()))
        {
            this.excludeSerials.add(caCert.getSerialNumber().getPositiveValue().longValue());
        }

        String sha1Fp = IoCertUtil.sha1sum(caCert.getEncoded());
        String sql = "SELECT ID FROM CAINFO WHERE SHA1_FP_CERT='" + sha1Fp + "'";
        Statement stmt = caDataSource.getConnection().createStatement();
        try
        {
            ResultSet rs = stmt.executeQuery(sql);
            if(rs.next())
            {
                caInfoId = rs.getInt("ID");
            }
            else
            {
                throw new Exception("CA Certificate and database configuration does not match");
            }
            rs.close();

            sql = "SELECT MIN(SERIAL) FROM CERT WHERE REVOKED=0 AND CAINFO_ID=" + caInfoId;
            rs = stmt.executeQuery(sql);
            rs.next();
            minSerial = rs.getLong(1);
            nextStartSerial = minSerial;

            sql = "SELECT MAX(SERIAL) FROM CERT WHERE REVOKED=0 AND CAINFO_ID=" + caInfoId;
            rs = stmt.executeQuery(sql);
            rs.next();
            maxSerial = rs.getLong(1);
        }finally
        {
            caDataSource.releaseResources(stmt, null);
        }
    }

    private List<Long> nextSerials()
    throws SQLException
    {
        List<Long> ret = new ArrayList<>(n);
        for(int i = 0; i < n; i++)
        {
            Long serial = nextSerial();
            if(serial != null)
            {
                ret.add(serial);
            }
            else
            {
                break;
            }
        }
        return ret;
    }

    private Long nextSerial()
    throws SQLException
    {
        synchronized (caDataSource)
        {
            if(maxCerts > 0)
            {
                int num = processedCerts.getAndAdd(1);
                if(num >= maxCerts)
                {
                    return null;
                }
            }

            Long firstSerial = serials.pollFirst();
            if(firstSerial != null)
            {
                return firstSerial;
            }

            if(noUnrevokedCerts == false)
            {
                String sql = "SERIAL FROM CERT WHERE REVOKED=0 AND CAINFO_ID=" + caInfoId +
                        " AND SERIAL > " + (nextStartSerial - 1) +
                        " AND SERIAL < " + (maxSerial + 1);
                sql = caDataSource.createFetchFirstSelectSQL(sql, 1000, "SERIAL");
                PreparedStatement stmt = caDataSource.getConnection().prepareStatement(sql);
                ResultSet rs = null;

                int n = 0;
                try
                {
                    rs = stmt.executeQuery();
                    while(rs.next())
                    {
                        n++;
                        long serial = rs.getLong("SERIAL");
                        if(serial + 1 > nextStartSerial)
                        {
                            nextStartSerial = serial + 1;
                        }
                        if(excludeSerials.contains(serial) == false)
                        {
                            serials.addLast(serial);
                        }
                    }
                }finally
                {
                    caDataSource.releaseResources(stmt, rs);
                }

                if(n == 0)
                {
                    System.out.println("No unrevoked certificate");
                    System.out.flush();
                }

                if(n < 1000)
                {
                    noUnrevokedCerts = true;
                }
            }

            return serials.pollFirst();
        }
    }

    class Testor implements Runnable
    {

        @Override
        public void run()
        {
            while(stop() == false && getErrorAccout() < 1)
            {
                List<Long> serialNumbers;
                try
                {
                    serialNumbers = nextSerials();
                } catch (SQLException e)
                {
                    account(1, 1);
                    break;
                }

                if(serialNumbers == null || serialNumbers.isEmpty())
                {
                    break;
                }

                int size = serialNumbers.size();
                int nSucc = testNext(serialNumbers);
                int failed = size - nSucc;
                if(failed < 0)
                {
                    failed = size;
                }
                account(size, failed);
            }
        }

        private int testNext(List<Long> serialNumbers)
        {
            RevokeCertRequestType request = new RevokeCertRequestType();
            int id = 1;
            for(Long serialNumber : serialNumbers)
            {
                CRLReason reason = reasons[(int) (serialNumber % reasons.length)];
                RevokeCertRequestEntryType entry = new RevokeCertRequestEntryType(
                        Integer.toString(id++), caSubject, BigInteger.valueOf(serialNumber),
                        reason.getCode(), null);
                request.addRequestEntry(entry);
            }

            Map<String, CertIDOrError> result;
            try
            {
                result = raWorker.revokeCerts(request);
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

            int nSuccess = 0;
            for(CertIDOrError entry : result.values())
            {
                if(entry.getCertId() != null)
                {
                    nSuccess++;
                }
            }
            return nSuccess;
        }
    }

}
