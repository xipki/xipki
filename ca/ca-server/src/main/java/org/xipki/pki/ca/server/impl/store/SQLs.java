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

package org.xipki.pki.ca.server.impl.store;

import java.util.Date;

import org.xipki.commons.common.LruCache;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.datasource.DataSourceWrapper;

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

    static final String CLEAR_DELTACRL_CACHE =
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

    private static final String CORESQL_CERT_FOR_ID =
        "PID,RID,REV,RR,RT,RIT,CERT FROM CERT INNER JOIN CRAW ON CERT.ID=?"
        + " AND CRAW.CID=CERT.ID";

    private static final String CORESQL_RAWCERT_FOR_ID =
            "CERT FROM CRAW WHERE CID=?";

    private static final String CORESQL_CERT_WITH_REVINFO =
            "ID,REV,RR,RT,RIT,PID,CERT FROM CERT INNER JOIN CRAW ON CERT.CA_ID=?"
            + " AND CERT.SN=? AND CRAW.CID=CERT.ID";

    private static final String CORESQL_CERTINFO =
            "PID,RID,REV,RR,RT,RIT,CERT FROM CERT INNER JOIN CRAW ON CERT.CA_ID=? AND CERT.SN=?"
            + " AND CRAW.CID=CERT.ID";

    private static final String CORESQL_CERT_FOR_SUBJECT_ISSUED =
            "ID FROM CERT WHERE CA_ID=? AND FP_S=?";

    private static final String CORESQL_CERT_FOR_KEY_ISSUED =
            "ID FROM CERT WHERE CA_ID=? AND FP_K=?";

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

        this.sqlCaHasCrl = datasource.buildSelectFirstSql("ID FROM CRL WHERE CA_ID=?", 1);
        this.sqlContainsCertificates = datasource.buildSelectFirstSql(
                "ID FROM CERT WHERE CA_ID=? AND EE=?", 1);
        this.sqlCertForId = datasource.buildSelectFirstSql(CORESQL_CERT_FOR_ID, 1);
        this.sqlRawCertForId = datasource.buildSelectFirstSql(CORESQL_RAWCERT_FOR_ID, 1);
        this.sqlCertWithRevInfo = datasource.buildSelectFirstSql(CORESQL_CERT_WITH_REVINFO, 1);
        this.sqlCertInfo = datasource.buildSelectFirstSql(CORESQL_CERTINFO, 1);
        this.sqlCertprofileForCertId = datasource.buildSelectFirstSql(
                "PID FROM CERT WHERE ID=? AND CA_ID=?", 1);
        this.sqlCertprofileForSerial = datasource.buildSelectFirstSql(
                "PID FROM CERT WHERE SN=? AND CA_ID=?", 1);
        this.sqlActiveUserInfoForName = datasource.buildSelectFirstSql(
                "ID,PASSWORD FROM USERNAME WHERE NAME=? AND ACTIVE=1", 1);
        this.sqlActiveUserNameForId = datasource.buildSelectFirstSql(
                "NAME FROM USERNAME WHERE ID=? AND ACTIVE=1", 1);
        this.sqlCaHasUser = datasource.buildSelectFirstSql(
                "PERMISSIONS,PROFILES FROM CA_HAS_USER WHERE CA_ID=? AND USER_ID=?", 1);
        this.sqlKnowsCertForSerial = datasource.buildSelectFirstSql(
                "UID FROM CERT WHERE SN=? AND CA_ID=?", 1);
        this.sqlRevForId = datasource.buildSelectFirstSql(
                "SN,EE,REV,RR,RT,RIT FROM CERT WHERE ID=?", 1);
        this.sqlCertStatusForSubjectFp = datasource.buildSelectFirstSql(
                "REV FROM CERT WHERE FP_S=? AND CA_ID=?", 1);
        this.sqlCertforSubjectIssued = datasource.buildSelectFirstSql(
                CORESQL_CERT_FOR_SUBJECT_ISSUED, 1);
        this.sqlCertForKeyIssued = datasource.buildSelectFirstSql(CORESQL_CERT_FOR_KEY_ISSUED,
                1);
        this.sqlLatestSerialForSubjectLike = datasource.buildSelectFirstSql(
                "SUBJECT FROM CERT WHERE SUBJECT LIKE ?", 1, "NBEFORE DESC");
        this.sqlLatestSerialForCertprofileAndSubjectLike = datasource.buildSelectFirstSql(
                "NBEFORE FROM CERT WHERE PID=? AND SUBJECT LIKE ?", 1, "NBEFORE ASC");
        this.sqlCrl = datasource.buildSelectFirstSql(
                "THISUPDATE,CRL FROM CRL WHERE CA_ID=?", 1, "THISUPDATE DESC");
        this.sqlCrlWithNo = datasource.buildSelectFirstSql(
                "THISUPDATE,CRL FROM CRL WHERE CA_ID=? AND CRL_NO=?", 1, "THISUPDATE DESC");
        this.sqlReqIdForSerial = datasource.buildSelectFirstSql(
                "REQCERT.RID as REQ_ID FROM REQCERT INNER JOIN CERT ON CERT.CA_ID=? "
                + "AND CERT.SN=? AND REQCERT.CID=CERT.ID", 1);
        this.sqlReqForId = datasource.buildSelectFirstSql(
                "DATA FROM REQUEST WHERE ID=?", 1);
    } // constructor

    String getSqlCidFromPublishQueue(final int numEntries) {
        String sql = cacheSqlCidFromPublishQueue.get(numEntries);
        if (sql == null) {
            sql = datasource.buildSelectFirstSql(
                    "CID FROM PUBLISHQUEUE WHERE PID=? AND CA_ID=?", numEntries, "CID ASC");
            cacheSqlCidFromPublishQueue.put(numEntries, sql);
        }
        return sql;
    }

    String getSqlExpiredSerials(final int numEntries) {
        String sql = cacheSqlExpiredSerials.get(numEntries);
        if (sql == null) {
            sql = datasource.buildSelectFirstSql(
                    "SN FROM CERT WHERE CA_ID=? AND NAFTER<?", numEntries);
            cacheSqlExpiredSerials.put(numEntries, sql);
        }
        return sql;
    }

    String getSqlSuspendedSerials(final int numEntries) {
        String sql = cacheSqlSuspendedSerials.get(numEntries);
        if (sql == null) {
            sql = datasource.buildSelectFirstSql(
                    "SN FROM CERT WHERE CA_ID=? AND LUPDATE<? AND RR=?", numEntries);
            cacheSqlSuspendedSerials.put(numEntries, sql);
        }
        return sql;
    }

    String getSqlDeltaCrlCacheIds(final int numEntries) {
        String sql = cacheSqlDeltaCrlCacheIds.get(numEntries);
        if (sql == null) {
            sql = datasource.buildSelectFirstSql(
                    "ID FROM DELTACRL_CACHE WHERE ID>? AND CA_ID=?", numEntries, "ID ASC");
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
            sql = datasource.buildSelectFirstSql(coreSql, numEntries, "ID ASC");
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
            sql = datasource.buildSelectFirstSql(coreSql, numEntries, "ID ASC");
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
        return datasource.buildSelectFirstSql(sb.toString(), numEntries, "ID ASC");
    }

}

