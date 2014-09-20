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
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedDeque;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.client.api.RAWorker;
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
    private final Set<Long> excludeSerials;
    private final ConcurrentLinkedDeque<Long> serials = new ConcurrentLinkedDeque<>();
    private int caInfoId;
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
            DataSourceWrapper caDataSource, Set<Long> excludeSerials)
    throws Exception
    {
        ParamChecker.assertNotNull("raWorker", raWorker);
        ParamChecker.assertNotNull("caCert", caCert);
        ParamChecker.assertNotNull("caDataSource", caDataSource);

        this.raWorker = raWorker;
        this.caDataSource = caDataSource;
        this.caSubject = caCert.getSubject();
        if(excludeSerials == null)
        {
            this.excludeSerials = Collections.emptySet();
        }
        else
        {
            this.excludeSerials = excludeSerials;
        }

        String sha1Fp = IoCertUtil.sha1sum(caCert.getEncoded());
        String sql = "SELECT ID FROM CAINFO WHERE SHA1_FP_CERT='" + sha1Fp + "'";
        Statement stmt = caDataSource.getConnection().createStatement();
        ResultSet rs = null;
        try
        {
            rs = stmt.executeQuery(sql);
            if(rs.next())
            {
                caInfoId = rs.getInt("ID");
            }
            else
            {
                throw new Exception("CA Certificate and database configuration does not match");
            }
        }finally
        {
            caDataSource.releaseResources(stmt, rs);
        }
    }

    private void nextSerials()
    throws SQLException
    {
        synchronized (caDataSource)
        {
            if(noUnrevokedCerts)
            {
                return;
            }

            String sql = "SERIAL FROM CERT WHERE REVOKED=0 AND CAINFO_ID=" + caInfoId;
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
            }

            if(n < 1000)
            {
                noUnrevokedCerts = true;
            }
        }
    }

    private Long nextSerial()
    throws SQLException
    {
        Long serial = serials.pollFirst();
        if(serial == null)
        {
            nextSerials();
        }
        return serial;
    }

    class Testor implements Runnable
    {

        @Override
        public void run()
        {
            while(stop() == false && getErrorAccout() < 1)
            {
                Long serial;
                try
                {
                    serial = nextSerial();
                } catch (SQLException e)
                {
                    account(1, 1);
                    break;
                }

                if(serial == null)
                {
                    break;
                }

                boolean succ = testNext(serial);
                account(1, succ ? 0 : 1);
            }
        }

        private boolean testNext(long serialNumber)
        {
            CertIDOrError result;
            try
            {
                CRLReason reason = reasons[(int) (serialNumber % reasons.length)];
                result = raWorker.revokeCert(caSubject, BigInteger.valueOf(serialNumber), reason.getCode());
            } catch (RAWorkerException | PKIErrorException e)
            {
                LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
                return false;
            }

            if(result == null)
            {
                return false;
            }

            return result.getCertId() != null;
        }
    }

    @Override
    protected boolean stop()
    {
        if(noUnrevokedCerts && serials.isEmpty())
        {
            return true;
        }

        return super.stop();
    }

}
