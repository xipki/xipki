/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.server.impl.store;

import java.util.Date;

import org.xipki.common.LruCache;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

// CHECKSTYLE:SKIP
class SQLs {

    static final String SQL_ADD_CERT =
            "INSERT INTO CERT (ID,ART,LUPDATE,SN,SUBJECT,FP_S,FP_RS,NBEFORE,NAFTER,REV,PID,"
            + "CA_ID,RID,UID,FP_K,EE,RTYPE,TID) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    static final String SQL_ADD_CRAW =
            "INSERT INTO CRAW (CID,SHA1,REQ_SUBJECT,CERT) VALUES (?,?,?,?)";

    static final String SQL_REVOKE_CERT =
            "UPDATE CERT SET LUPDATE=?,REV=?,RT=?,RIT=?,RR=? WHERE ID=?";

    static final String SQL_REVOKE_SUSPENDED_CERT =
            "UPDATE CERT SET LUPDATE=?,RR=? WHERE ID=?";

    static final String SQL_INSERT_PUBLISHQUEUE =
            "INSERT INTO PUBLISHQUEUE (PID,CA_ID,CID) VALUES (?,?,?)";

    static final String SQL_REMOVE_PUBLISHQUEUE =
            "DELETE FROM PUBLISHQUEUE WHERE PID=? AND CID=?";

    static final String SQL_MAXID_DELTACRL_CACHE =
            "SELECT MAX(ID) FROM DELTACRL_CACHE WHERE CA_ID=?";

    static final String SQL_CLEAR_DELTACRL_CACHE =
            "DELETE FROM DELTACRL_CACHE WHERE ID<? AND CA_ID=?";

    static final String SQL_MAX_CRLNO =
            "SELECT MAX(CRL_NO) FROM CRL WHERE CA_ID=?";

    static final String SQL_MAX_THISUPDAATE_CRL =
            "SELECT MAX(THISUPDATE) FROM CRL WHERE CA_ID=?";

    static final String SQL_ADD_CRL =
            "INSERT INTO CRL (ID,CA_ID,CRL_NO,THISUPDATE,NEXTUPDATE,DELTACRL,BASECRL_NO,CRL)"
            + " VALUES (?,?,?,?,?,?,?,?)";

    static final String SQL_ADD_DELTACRL_CACHE =
            "INSERT INTO DELTACRL_CACHE (ID,CA_ID,SN) VALUES (?,?,?)";

    static final String SQL_REMOVE_CERT =
            "DELETE FROM CERT WHERE CA_ID=? AND SN=?";

    static final String SQL_DELETE_UNREFERENCED_REQUEST =
            "DELETE FROM REQUEST WHERE ID NOT IN (SELECT req.RID FROM REQCERT req)";

    static final String SQL_ADD_REQUEST =
            "INSERT INTO REQUEST (ID,LUPDATE,DATA) VALUES(?,?,?)";

    static final String SQL_ADD_REQCERT =
            "INSERT INTO REQCERT (ID,RID,CID) VALUES(?,?,?)";

    final String sqlCaHasCrl;

    final String sqlContainsCertificates;

    final String sqlCertForId;

    final String sqlRawCertForId;

    final String sqlCertWithRevInfo;

    final String sqlCertInfo;

    final String sqlCertprofileForCertId;

    final String sqlCertprofileForSerial;

    final String sqlActiveUserInfoForName;

    final String sqlActiveUserNameForId;

    final String sqlCaHasUser;

    final String sqlKnowsCertForSerial;

    final String sqlRevForId;

    final String sqlCertStatusForSubjectFp;

    final String sqlCertforSubjectIssued;

    final String sqlCertForKeyIssued;

    final String sqlLatestSerialForSubjectLike;

    final String sqlLatestSerialForCertprofileAndSubjectLike;

    final String sqlCrl;

    final String sqlCrlWithNo;

    final String sqlReqIdForSerial;

    final String sqlReqForId;

    private final DataSourceWrapper datasource;

    private final LruCache<Integer, String> cacheSqlCidFromPublishQueue = new LruCache<>(5);

    private final LruCache<Integer, String> cacheSqlExpiredSerials = new LruCache<>(5);

    private final LruCache<Integer, String> cacheSqlSuspendedSerials = new LruCache<>(5);

    private final LruCache<Integer, String> cacheSqlDeltaCrlCacheIds = new LruCache<>(5);

    private final LruCache<Integer, String> cacheSqlRevokedCerts = new LruCache<>(5);

    private final LruCache<Integer, String> cacheSqlRevokedCertsWithEe = new LruCache<>(5);

    private final LruCache<Integer, String> cacheSqlSerials = new LruCache<>(5);

    private final LruCache<Integer, String> cacheSqlSerialsRevoked = new LruCache<>(5);

    SQLs(final DataSourceWrapper datasource) {
        this.datasource = ParamUtil.requireNonNull("datasource", datasource);

        this.sqlCaHasCrl = datasource.buildSelectFirstSql(1,
                "ID FROM CRL WHERE CA_ID=?");
        this.sqlContainsCertificates = datasource.buildSelectFirstSql(1,
                "ID FROM CERT WHERE CA_ID=? AND EE=?");

        this.sqlCertForId = datasource.buildSelectFirstSql(1,
                "PID,RID,REV,RR,RT,RIT,CERT FROM CERT INNER JOIN CRAW ON CERT.ID=?"
                + " AND CRAW.CID=CERT.ID");
        this.sqlRawCertForId = datasource.buildSelectFirstSql(1,
                "CERT FROM CRAW WHERE CID=?");
        this.sqlCertWithRevInfo = datasource.buildSelectFirstSql(1,
                "ID,REV,RR,RT,RIT,PID,CERT FROM CERT INNER JOIN CRAW ON CERT.CA_ID=?"
                + " AND CERT.SN=? AND CRAW.CID=CERT.ID");
        this.sqlCertInfo = datasource.buildSelectFirstSql(1,
                "PID,RID,REV,RR,RT,RIT,CERT FROM CERT INNER JOIN CRAW ON CERT.CA_ID=? AND CERT.SN=?"
                + " AND CRAW.CID=CERT.ID");
        this.sqlCertprofileForCertId = datasource.buildSelectFirstSql(1,
                "PID FROM CERT WHERE ID=? AND CA_ID=?");
        this.sqlCertprofileForSerial = datasource.buildSelectFirstSql(1,
                "PID FROM CERT WHERE SN=? AND CA_ID=?");
        this.sqlActiveUserInfoForName = datasource.buildSelectFirstSql(1,
                "ID,PASSWORD FROM TUSER WHERE NAME=? AND ACTIVE=1");
        this.sqlActiveUserNameForId = datasource.buildSelectFirstSql(1,
                "NAME FROM TUSER WHERE ID=? AND ACTIVE=1");
        this.sqlCaHasUser = datasource.buildSelectFirstSql(1,
                "PERMISSION,PROFILES FROM CA_HAS_USER WHERE CA_ID=? AND USER_ID=?");
        this.sqlKnowsCertForSerial = datasource.buildSelectFirstSql(1,
                "UID FROM CERT WHERE SN=? AND CA_ID=?");
        this.sqlRevForId = datasource.buildSelectFirstSql(1,
                "SN,EE,REV,RR,RT,RIT FROM CERT WHERE ID=?");
        this.sqlCertStatusForSubjectFp = datasource.buildSelectFirstSql(1,
                "REV FROM CERT WHERE FP_S=? AND CA_ID=?");
        this.sqlCertforSubjectIssued = datasource.buildSelectFirstSql(1,
                "ID FROM CERT WHERE CA_ID=? AND FP_S=?");
        this.sqlCertForKeyIssued = datasource.buildSelectFirstSql(1,
                "ID FROM CERT WHERE CA_ID=? AND FP_K=?");
        this.sqlLatestSerialForSubjectLike = datasource.buildSelectFirstSql(1, "NBEFORE DESC",
                "SUBJECT FROM CERT WHERE SUBJECT LIKE ?");
        this.sqlLatestSerialForCertprofileAndSubjectLike = datasource.buildSelectFirstSql(1,
                "NBEFORE ASC",
                "NBEFORE FROM CERT WHERE PID=? AND SUBJECT LIKE ?");
        this.sqlCrl = datasource.buildSelectFirstSql(1, "THISUPDATE DESC",
                "THISUPDATE,CRL FROM CRL WHERE CA_ID=?");
        this.sqlCrlWithNo = datasource.buildSelectFirstSql(1, "THISUPDATE DESC",
                "THISUPDATE,CRL FROM CRL WHERE CA_ID=? AND CRL_NO=?");
        this.sqlReqIdForSerial = datasource.buildSelectFirstSql(1,
                "REQCERT.RID as REQ_ID FROM REQCERT INNER JOIN CERT ON CERT.CA_ID=? "
                + "AND CERT.SN=? AND REQCERT.CID=CERT.ID");
        this.sqlReqForId = datasource.buildSelectFirstSql(1,
                "DATA FROM REQUEST WHERE ID=?");
    } // constructor

    String getSqlCidFromPublishQueue(final int numEntries) {
        String sql = cacheSqlCidFromPublishQueue.get(numEntries);
        if (sql == null) {
            sql = datasource.buildSelectFirstSql(numEntries, "CID ASC",
                    "CID FROM PUBLISHQUEUE WHERE PID=? AND CA_ID=?");
            cacheSqlCidFromPublishQueue.put(numEntries, sql);
        }
        return sql;
    }

    String getSqlExpiredSerials(final int numEntries) {
        String sql = cacheSqlExpiredSerials.get(numEntries);
        if (sql == null) {
            sql = datasource.buildSelectFirstSql(numEntries,
                    "SN FROM CERT WHERE CA_ID=? AND NAFTER<?");
            cacheSqlExpiredSerials.put(numEntries, sql);
        }
        return sql;
    }

    String getSqlSuspendedSerials(final int numEntries) {
        String sql = cacheSqlSuspendedSerials.get(numEntries);
        if (sql == null) {
            sql = datasource.buildSelectFirstSql(numEntries,
                    "SN FROM CERT WHERE CA_ID=? AND LUPDATE<? AND RR=?");
            cacheSqlSuspendedSerials.put(numEntries, sql);
        }
        return sql;
    }

    String getSqlDeltaCrlCacheIds(final int numEntries) {
        String sql = cacheSqlDeltaCrlCacheIds.get(numEntries);
        if (sql == null) {
            sql = datasource.buildSelectFirstSql(numEntries, "ID ASC",
                    "ID FROM DELTACRL_CACHE WHERE ID>? AND CA_ID=?");
            cacheSqlDeltaCrlCacheIds.put(numEntries, sql);
        }
        return sql;
    }

    String getSqlRevokedCerts(final int numEntries, final boolean withEe) {
        LruCache<Integer, String> cache = withEe ? cacheSqlRevokedCertsWithEe
                : cacheSqlRevokedCerts;
        String sql = cache.get(numEntries);
        if (sql == null) {
            String coreSql =
                    "ID,SN,RR,RT,RIT FROM CERT WHERE ID>? AND CA_ID=? AND REV=1 AND NAFTER>?";
            if (withEe) {
                coreSql += " AND EE=?";
            }
            sql = datasource.buildSelectFirstSql(numEntries, "ID ASC", coreSql);
            cache.put(numEntries, sql);
        }
        return sql;
    }

    String getSqlSerials(final int numEntries, final boolean onlyRevoked) {
        LruCache<Integer, String> cache = onlyRevoked ? cacheSqlSerialsRevoked :
            cacheSqlSerials;
        String sql = cache.get(numEntries);
        if (sql == null) {
            String coreSql = "ID,SN FROM CERT WHERE ID>? AND CA_ID=?";
            if (onlyRevoked) {
                coreSql += "AND REV=1";
            }
            sql = datasource.buildSelectFirstSql(numEntries, "ID ASC", coreSql);
            cache.put(numEntries, sql);
        }
        return sql;
    }

    String getSqlSerials(final int numEntries, final Date notExpiredAt,
            final boolean onlyRevoked, final boolean withEe) {
        StringBuilder sb = new StringBuilder("ID,SN FROM CERT WHERE ID>? AND CS=?");
        if (notExpiredAt != null) {
            sb.append(" AND NAFTER>?");
        }
        if (onlyRevoked) {
            sb.append(" AND REV=1");
        }
        if (withEe) {
            sb.append(" AND EE=?");
        }
        return datasource.buildSelectFirstSql(numEntries, "ID ASC", sb.toString());
    }

}

