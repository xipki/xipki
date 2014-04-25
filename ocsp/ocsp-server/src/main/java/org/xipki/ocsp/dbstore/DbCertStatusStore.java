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

package org.xipki.ocsp.dbstore;

import java.math.BigInteger;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.database.api.DataSource;
import org.xipki.ocsp.IssuerEntry;
import org.xipki.ocsp.IssuerHashNameAndKey;
import org.xipki.ocsp.IssuerStore;
import org.xipki.ocsp.api.CertRevocationInfo;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.CertStatusStore;
import org.xipki.ocsp.api.CertStatusStoreException;
import org.xipki.ocsp.api.HashAlgoType;
import org.xipki.security.common.ParamChecker;

public class DbCertStatusStore implements CertStatusStore
{
    private class StoreUpdateService implements Runnable
    {
        @Override
        public void run()
        {
            initIssuerStore();
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(DbCertStatusStore.class);

    private final String name;
    private final DataSource dataSource;
    private final boolean unknownSerialAsGood;

    private IssuerStore issuerStore;
    private AuditLoggingService auditLoggingService;

    private boolean initialized = false;

    public DbCertStatusStore(String name, DataSource dataSource, boolean unknownSerialAsGood)
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotNull("dataSource", dataSource);

        this.name = name;
        this.dataSource = dataSource;
        this.unknownSerialAsGood = unknownSerialAsGood;

        initIssuerStore();

        StoreUpdateService storeUpdateService = new StoreUpdateService();
        ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
        scheduledThreadPoolExecutor.scheduleAtFixedRate(
                storeUpdateService, 60, 60, TimeUnit.SECONDS);
    }

    private synchronized void initIssuerStore()
    {
        try
        {
            if(initialized)
            {
                String sql = "SELECT id FROM issuer";
                PreparedStatement ps = borrowPreparedStatement(sql);
                ResultSet rs = null;
                
                try
                {
                    Set<Integer> newIds = new HashSet<Integer>();

                    rs = ps.executeQuery();
                    while(rs.next())
                    {
                        int id = rs.getInt("id");
                        newIds.add(id);
                    }

                    // no change in the issuerStore
                    Set<Integer> ids = issuerStore.getIds();
                    if(ids.size() == newIds.size() && ids.containsAll(newIds) && newIds.containsAll(ids))
                    {
                        return;
                    }
                }finally
                {
                	releaseDbResources(ps, rs);
                }
            }

            HashAlgoType[] hashAlgoTypes = {HashAlgoType.SHA1, HashAlgoType.SHA224, HashAlgoType.SHA256,
                    HashAlgoType.SHA384, HashAlgoType.SHA512};

            StringBuilder sb = new StringBuilder();
            sb.append("SELECT id");
            for(HashAlgoType hashAlgoType : hashAlgoTypes)
            {
                String hashAlgo = hashAlgoType.name().toLowerCase();
                sb.append(", ").append(hashAlgo).append("_fp_name");
                sb.append(", ").append(hashAlgo).append("_fp_key");
            };
            sb.append(" FROM issuer");

            String sql = sb.toString();
            PreparedStatement ps = borrowPreparedStatement(sql);

            ResultSet rs = null;
            try
            {
                rs = ps.executeQuery();
                List<IssuerEntry> caInfos = new LinkedList<IssuerEntry>();
                while(rs.next())
                {
                    int id = rs.getInt("id");

                    Map<HashAlgoType, IssuerHashNameAndKey> hashes = new HashMap<HashAlgoType, IssuerHashNameAndKey>();
                    for(HashAlgoType hashAlgoType : hashAlgoTypes)
                    {
                        String hashAlgo = hashAlgoType.name().toLowerCase();
                        String hash_name = rs.getString(hashAlgo + "_fp_name");
                        String hash_key = rs.getString(hashAlgo + "_fp_key");
                        IssuerHashNameAndKey hash = new IssuerHashNameAndKey(
                                hashAlgoType, Hex.decode(hash_name), Hex.decode(hash_key));
                        hashes.put(hashAlgoType, hash);
                    }

                    IssuerEntry caInfoEntry = new IssuerEntry(id, hashes, null);
                    caInfos.add(caInfoEntry);
                }

                initialized = false;
                this.issuerStore = new IssuerStore(caInfos);
                LOG.info("Updated CertStore: {}", name);
                initialized = true;
            }finally
            {
            	releaseDbResources(ps, rs);
            }
        }catch(Exception e)
        {
            LOG.error("Could not executing initIssurStore() for {},  {}: {}",
                    new Object[]{name, e.getClass().getName(), e.getMessage()});
            LOG.debug("Could not executing initIssurStore()", e);
        }
    }

    @Override
    public CertStatusInfo getCertStatus(
            HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash,
            BigInteger serialNumber,
            boolean includeCertHash,
            HashAlgoType certHashAlgo)
    throws CertStatusStoreException
    {
        // wait for max. 0.5 second
        int n = 5;
        while(initialized == false && (n-- > 0))
        {
            try
            {
                Thread.sleep(100);
            }catch(InterruptedException e)
            {
            }
        }

        if(initialized == false)
        {
            throw new CertStatusStoreException("Initialization of CertStore is still in process");
        }

        if(includeCertHash && certHashAlgo == null)
        {
            certHashAlgo = hashAlgo;
        }

        try
        {
            Date thisUpdate = new Date();

            IssuerEntry issuer = issuerStore.getIssuerForFp(hashAlgo, issuerNameHash, issuerKeyHash);
            if(issuer == null)
            {
                return CertStatusInfo.getIssuerUnknownCertStatusInfo(thisUpdate, null);
            }

            final String sql =
                    "id, revocated, rev_reason, rev_time, rev_invalidity_time" +
                    " FROM cert" +
                    " WHERE issuer_id=? AND serial=?";

            PreparedStatement ps = borrowPreparedStatement(createFetchFirstSelectSQL(sql, 1));
            ResultSet rs = null;

            try
            {
                ps.setInt(1, issuer.getId());
                ps.setLong(2, serialNumber.longValue());

                rs = ps.executeQuery();

                if(rs.next())
                {
                    byte[] certHash = null;
                    if(includeCertHash)
                    {
                        int certId = rs.getInt("id");
                        certHash = getCertHash(certId, certHashAlgo);
                    }

                    CertStatusInfo certStatusInfo;
                    boolean revocated = rs.getBoolean("revocated");
                    if(revocated)
                    {
                        int reason = rs.getInt("rev_reason");
                        long revocationTime = rs.getLong("rev_time");
                        long invalidatityTime = rs.getLong("rev_invalidity_time");
                        CertRevocationInfo revInfo = new CertRevocationInfo(reason, new Date(revocationTime * 1000),
                                new Date(invalidatityTime * 1000));
                        certStatusInfo = CertStatusInfo.getRevocatedCertStatusInfo(revInfo, certHashAlgo, certHash,
                                thisUpdate, null);
                    }
                    else
                    {
                        certStatusInfo = CertStatusInfo.getGoodCertStatusInfo(certHashAlgo, certHash, thisUpdate, null);
                    }

                    return certStatusInfo;
                }
                else
                {
                    return unknownSerialAsGood ?
                            CertStatusInfo.getGoodCertStatusInfo(certHashAlgo, null, thisUpdate, null) :
                            CertStatusInfo.getUnknownCertStatusInfo(thisUpdate, null);
                }
            }finally
            {
            	releaseDbResources(ps, rs);
            }
        }catch(SQLException e)
        {
            throw new CertStatusStoreException(e);
        }
    }

    private byte[] getCertHash(int certId, HashAlgoType hashAlgo)
    throws SQLException
    {
        final String sql = hashAlgo.name().toLowerCase() + "_fp" +
                " FROM certhash WHERE cert_id=?";
        PreparedStatement ps = borrowPreparedStatement(createFetchFirstSelectSQL(sql, 1));
        ResultSet rs = null;
        try
        {
            ps.setInt(1, certId);
            rs = ps.executeQuery();

            if(rs.next())
            {
                String hexHash = rs.getString(1);
                return Hex.decode(hexHash);
            }
            else
            {
                return null;
            }
        }finally
        {
        	releaseDbResources(ps, rs);
        }
    }

    private String createFetchFirstSelectSQL(String coreSql, int rows)
    {
        String prefix = "SELECT";
        String suffix = "";

        switch(dataSource.getDatabaseType())
        {
            case DB2:
                suffix = "FETCH FIRST " + rows + " ROWS ONLY";
                break;
            case INFORMIX:
                prefix = "SELECT FIRST " + rows;
                break;
            case MSSQL2000:
                prefix = "SELECT TOP " + rows;
                break;
            case MYSQL:
                suffix = "LIMIT " + rows;
                break;
            case ORACLE:
                 suffix = "AND ROWNUM <= " + rows;
                break;
            case POSTGRESQL:
                suffix = " FETCH FIRST " + rows + " ROWS ONLY";
                break;
            default:
                break;
        }

        return prefix + " " + coreSql + " " + suffix;
    }

    /**
     *
     * @return the next idle preparedStatement, {@code null} will be returned
     *         if no PreparedStament can be created within 5 seconds
     * @throws SQLException
     */
    private PreparedStatement borrowPreparedStatement(String sqlQuery)
    throws SQLException
    {
        PreparedStatement ps = null;
        Connection c = dataSource.getConnection(5000);
        if(c != null)
        {
            LOG.debug("no idle PreparedStatement, create new instance");
            ps = c.prepareStatement(sqlQuery);
        }
        if(ps == null)
        {
            throw new SQLException("Cannot create prepared statement for " + sqlQuery);
        }
        return ps;
    }

    @Override
    public boolean isHealthy()
    {
        final String sql = "SELECT id FROM issuer";

        try
        {
            PreparedStatement ps = borrowPreparedStatement(sql);
            ResultSet rs = null;
            try
            {
                rs = ps.executeQuery();
                return true;
            }finally
            {
            	releaseDbResources(ps, rs);
            }
        }catch(Exception e)
        {
            LOG.error("isHealthy(). {}: {}", e.getClass().getName(), e.getMessage());
            LOG.debug("isHealthy()", e);
            return false;
        }
    }

    @Override
    public String getName()
    {
        return name;
    }

    @Override
    public AuditLoggingService getAuditLoggingService()
    {
        return auditLoggingService;
    }

    @Override
    public void setAuditLoggingService(AuditLoggingService auditLoggingService)
    {
        this.auditLoggingService = auditLoggingService;
    }    
    
    private void releaseDbResources(PreparedStatement ps, ResultSet rs)
    {
        if(rs != null)
        {
            try
            {
                rs.close();
            }catch(Throwable t)
            {
                LOG.warn("Cannot return close ResultSet", t);
            }
        }

        try
        {
            Connection conn = ps.getConnection();
            ps.close();
            dataSource.returnConnection(conn);
        }catch(Throwable t)
        {
            LOG.warn("Cannot return prepared statement and connection", t);
        }
    }

}
