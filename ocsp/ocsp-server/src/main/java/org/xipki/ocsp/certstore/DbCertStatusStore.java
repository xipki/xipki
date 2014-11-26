/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ocsp.certstore;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
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
import org.xipki.common.CRLReason;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.HashAlgoType;
import org.xipki.common.LogUtil;
import org.xipki.common.ParamChecker;
import org.xipki.datasource.api.DataSourceFactory;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.ocsp.IssuerEntry;
import org.xipki.ocsp.IssuerStore;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.CertStatusStore;
import org.xipki.ocsp.api.CertStatusStoreException;
import org.xipki.ocsp.api.IssuerHashNameAndKey;
import org.xipki.security.api.PasswordResolver;

/**
 * @author Lijun Liao
 */

public class DbCertStatusStore extends CertStatusStore
{
    private static final Logger LOG = LoggerFactory.getLogger(DbCertStatusStore.class);

    private static class SimpleIssuerEntry
    {
        private final int id;
        private final boolean revoked;
        private final long revocationTimeInMs;

        public SimpleIssuerEntry(int id, boolean revoked, long revocationTimeInMs)
        {
            this.id = id;
            this.revoked = revoked;
            this.revocationTimeInMs = revocationTimeInMs;
        }

        public boolean match(IssuerEntry issuer)
        {
            if(id != issuer.getId())
            {
                return false;
            }

            if(revoked != issuer.isRevoked())
            {
                return false;
            }

            if(revocationTimeInMs == 0)
            {
                return issuer.getRevocationTime() == null;
            }
            else
            {
                Date issuerRevTime = issuer.getRevocationTime();
                if(issuerRevTime == null)
                {
                    return false;
                }
                else
                {
                    return revocationTimeInMs == issuerRevTime.getTime();
                }
            }
        }
    }

    private class StoreUpdateService implements Runnable
    {
        @Override
        public void run()
        {
            initIssuerStore();
        }
    }

    private final DataSourceWrapper dataSource;
    private Set<String> issuerSHA1FPs;

    private IssuerStore issuerStore;

    private boolean initialized = false;
    private boolean initializationFailed = false;

    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

    public DbCertStatusStore(String name, DataSourceWrapper dataSource, Set<X509Certificate> issuers)
    {
        super(name);
        ParamChecker.assertNotNull("dataSource", dataSource);
        this.dataSource = dataSource;
        if(issuers != null)
        {
            this.issuerSHA1FPs = new HashSet<>();
        }

        initIssuerStore();

        StoreUpdateService storeUpdateService = new StoreUpdateService();
        scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
        scheduledThreadPoolExecutor.scheduleAtFixedRate(
                storeUpdateService, 60, 60, TimeUnit.SECONDS);
    }

    @SuppressWarnings("resource")
    private synchronized void initIssuerStore()
    {
        try
        {
            if(initialized)
            {
                String sql = "SELECT ID, REVOKED, REV_TIME, SHA1_FP_CERT FROM ISSUER";
                PreparedStatement ps = borrowPreparedStatement(sql);
                ResultSet rs = null;

                try
                {
                    Map<Integer, SimpleIssuerEntry> newIssuers = new HashMap<>();

                    rs = ps.executeQuery();
                    while(rs.next())
                    {
                        if(issuerSHA1FPs != null)
                        {
                            String sha1Fp = rs.getString("SHA1_FP_CERT");
                            if(issuerSHA1FPs.contains(sha1Fp) == false)
                            {
                                continue;
                            }
                        }

                        int id = rs.getInt("ID");
                        boolean revoked = rs.getBoolean("REVOKED");
                        long revTime = rs.getLong("REV_TIME");

                        SimpleIssuerEntry issuerEntry = new SimpleIssuerEntry(id, revoked, revTime * 1000);
                        newIssuers.put(id, issuerEntry);
                    }

                    // no change in the issuerStore
                    Set<Integer> newIds = newIssuers.keySet();

                    Set<Integer> ids;
                    if(issuerStore != null)
                    {
                        ids = issuerStore.getIds();
                    }
                    else
                    {
                        ids = Collections.emptySet();
                    }

                    boolean issuersUnchanged =
                            ids.size() == newIds.size()
                            && ids.containsAll(newIds)
                            && newIds.containsAll(ids);

                    if(issuersUnchanged)
                    {
                        for(Integer id : newIds)
                        {
                            IssuerEntry entry = issuerStore.getIssuerForId(id);
                            SimpleIssuerEntry newEntry = newIssuers.get(id);
                            if(newEntry.match(entry))
                            {
                                issuersUnchanged = false;
                                break;
                            }
                        }
                    }

                    if(issuersUnchanged)
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
            sb.append("SELECT ID, NOTBEFORE, REVOKED, REV_TIME, SHA1_FP_CERT");
            for(HashAlgoType hashAlgoType : hashAlgoTypes)
            {
                String hashAlgo = hashAlgoType.name().toUpperCase();
                sb.append(", ").append(hashAlgo).append("_FP_NAME");
                sb.append(", ").append(hashAlgo).append("_FP_KEY");
            };
            sb.append(" FROM ISSUER");

            String sql = sb.toString();
            PreparedStatement ps = borrowPreparedStatement(sql);

            ResultSet rs = null;
            try
            {
                rs = ps.executeQuery();
                List<IssuerEntry> caInfos = new LinkedList<>();
                while(rs.next())
                {
                    String sha1Fp = rs.getString("SHA1_FP_CERT");
                    if(issuerSHA1FPs != null &&issuerSHA1FPs.contains(sha1Fp) == false)
                    {
                        continue;
                    }

                    int id = rs.getInt("ID");
                    long notBeforeInSecond = rs.getLong("NOTBEFORE");

                    Map<HashAlgoType, IssuerHashNameAndKey> hashes = new HashMap<>();
                    for(HashAlgoType hashAlgoType : hashAlgoTypes)
                    {
                        String hashAlgo = hashAlgoType.name().toUpperCase();
                        String hash_name = rs.getString(hashAlgo + "_FP_NAME");
                        String hash_key = rs.getString(hashAlgo + "_FP_KEY");
                        byte[] hashNameBytes = Hex.decode(hash_name);
                        byte[] hashKeyBytes = Hex.decode(hash_key);
                        IssuerHashNameAndKey hash = new IssuerHashNameAndKey(
                                hashAlgoType, hashNameBytes, hashKeyBytes);

                        if(hashAlgoType == HashAlgoType.SHA1)
                        {
                            for(IssuerEntry existingIssuer : caInfos)
                            {
                                if(existingIssuer.matchHash(hashAlgoType, hashNameBytes, hashKeyBytes))
                                {
                                    throw new Exception("Found at least two issuers with the same subject and key");
                                }
                            }
                        }
                        hashes.put(hashAlgoType, hash);
                    }

                    IssuerEntry caInfoEntry = new IssuerEntry(id, hashes, new Date(notBeforeInSecond * 1000));
                    boolean revoked = rs.getBoolean("REVOKED");
                    caInfoEntry.setRevoked(revoked);
                    if(revoked)
                    {
                        long l = rs.getLong("REV_TIME");
                        caInfoEntry.setRevocationTime(new Date(l * 1000));
                    }

                    caInfos.add(caInfoEntry);
                }

                initialized = false;
                this.issuerStore = new IssuerStore(caInfos);
                LOG.info("Updated CertStore: {}", getName());
                initializationFailed =false;
                initialized = true;
            }finally
            {
                releaseDbResources(ps, rs);
            }
        }catch(Exception e)
        {
            final String message = "Could not executing initializeStore()";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            initializationFailed = true;
            initialized = true;
        }
    }

    @Override
    public CertStatusInfo getCertStatus(
            HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash,
            BigInteger serialNumber, Set<String> excludeCertProfiles)
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

        if(initializationFailed)
        {
            throw new CertStatusStoreException("Initialization of CertStore failed");
        }

        HashAlgoType certHashAlgo = null;
        if(includeCertHash)
        {
            certHashAlgo = certHashAlgorithm == null ? hashAlgo : certHashAlgorithm;
        }

        try
        {
            Date thisUpdate = new Date();

            IssuerEntry issuer = issuerStore.getIssuerForFp(hashAlgo, issuerNameHash, issuerKeyHash);
            if(issuer == null)
            {
                return CertStatusInfo.getIssuerUnknownCertStatusInfo(thisUpdate, null);
            }

            final String sql = "ID, NOTBEFORE, REVOKED, REV_REASON, REV_TIME, REV_INVALIDITY_TIME, PROFILE" +
                    " FROM CERT WHERE ISSUER_ID=? AND SERIAL=?";

            ResultSet rs = null;
            CertStatusInfo certStatusInfo = null;

            PreparedStatement ps = borrowPreparedStatement(
                    dataSource.createFetchFirstSelectSQL(sql, 1));

            try
            {
                ps.setInt(1, issuer.getId());
                ps.setLong(2, serialNumber.longValue());

                rs = ps.executeQuery();

                boolean unknownOrIgnore = true;

                if(rs.next())
                {
                    unknownOrIgnore = false;

                    String certprofile = rs.getString("PROFILE");
                    if(excludeCertProfiles != null && excludeCertProfiles.contains(certprofile))
                    {
                        unknownOrIgnore = true;
                    }
                    else
                    {
                        byte[] certHash = null;
                        if(includeCertHash)
                        {
                            int certId = rs.getInt("ID");
                            certHash = getCertHash(certId, certHashAlgo);
                        }

                        boolean revoked = rs.getBoolean("REVOKED");
                        if(revoked)
                        {
                            int reason = rs.getInt("REV_REASON");
                            long revocationTime = rs.getLong("REV_TIME");
                            long invalidatityTime = rs.getLong("REV_INVALIDITY_TIME");

                            Date invTime = null;
                            if(invalidatityTime != 0 && invalidatityTime != revocationTime)
                            {
                                invTime = new Date(invalidatityTime * 1000);
                            }
                            CertRevocationInfo revInfo = new CertRevocationInfo(reason, new Date(revocationTime * 1000),
                                    invTime);
                            certStatusInfo = CertStatusInfo.getRevokedCertStatusInfo(revInfo, certHashAlgo, certHash,
                                    thisUpdate, null, certprofile);
                        }
                        else
                        {
                            certStatusInfo = CertStatusInfo.getGoodCertStatusInfo(certHashAlgo, certHash, thisUpdate,
                                    null, certprofile);
                        }
                    }
                }

                if(unknownOrIgnore)
                {
                    if(unknownSerialAsGood)
                    {
                        if(inheritCaRevocation && issuer.isRevoked())
                        {
                            CertRevocationInfo revocationInfo = new CertRevocationInfo(
                                    CRLReason.CA_COMPROMISE.getCode(), issuer.getRevocationTime(), null);
                            certStatusInfo = CertStatusInfo.getRevokedCertStatusInfo(revocationInfo,
                                    null, null, thisUpdate, null, null);
                        }
                        else
                        {
                            certStatusInfo = CertStatusInfo.getGoodCertStatusInfo(certHashAlgo, null, thisUpdate, null, null);
                        }
                    }
                    else
                    {
                        certStatusInfo = CertStatusInfo.getUnknownCertStatusInfo(thisUpdate, null);
                    }
                }
            }finally
            {
                releaseDbResources(ps, rs);
            }

            if(includeArchiveCutoff)
            {
                Date t;
                if(retentionInterval != 0)
                {
                    // expired certificate remains in status store for ever
                    if(retentionInterval < 0)
                    {
                        t = issuer.getCaNotBefore();
                    }
                    else
                    {
                        long nowÍnMs = System.currentTimeMillis();
                        long tInMs = Math.max(issuer.getCaNotBefore().getTime(), nowÍnMs - DAY * retentionInterval);
                        t = new Date(tInMs);
                    }

                    certStatusInfo.setArchiveCutOff(t);
                }
            }

            return certStatusInfo;
        }catch(SQLException e)
        {
            throw new CertStatusStoreException(e);
        }
    }

    private byte[] getCertHash(int certId, HashAlgoType hashAlgo)
    throws SQLException
    {
        final String sql = hashAlgo.name().toUpperCase() + "_FP FROM CERTHASH WHERE CERT_ID=?";
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(
                dataSource.createFetchFirstSelectSQL(sql, 1));
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
        Connection c = dataSource.getConnection();
        if(c != null)
        {
            ps = dataSource.prepareStatement(c, sqlQuery);
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
        final String sql = "SELECT ID FROM ISSUER";

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
            final String message = "isHealthy()";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            return false;
        }
    }

    private void releaseDbResources(Statement ps, ResultSet rs)
    {
        dataSource.releaseResources(ps, rs);
    }

    @Override
    public void init(String conf, DataSourceFactory datasourceFactory, PasswordResolver passwordResolver)
    throws CertStatusStoreException
    {
    }

    @Override
    public boolean start()
    {
        return true;
    }

    @Override
    public void shutdown()
    throws CertStatusStoreException
    {
        if(scheduledThreadPoolExecutor != null)
        {
            scheduledThreadPoolExecutor.shutdown();
            scheduledThreadPoolExecutor = null;
        }
    }

    @Override
    public boolean canResolveIssuer(HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash)
    {
        IssuerEntry issuer = issuerStore.getIssuerForFp(hashAlgo, issuerNameHash, issuerKeyHash);
        return issuer != null;
    }

    @Override
    public Set<IssuerHashNameAndKey> getIssuerHashNameAndKeys()
    {
        return issuerStore.getIssuerHashNameAndKeys();
    }

}
