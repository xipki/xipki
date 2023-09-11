// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.diffdb;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.mgmt.db.diffdb.QueueEntry.DigestEntrySet;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.StringUtil;

import java.io.Closeable;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Reader of certificate information for the comparison from the reference database.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class RefDigestReader implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(RefDigestReader.class);

  private final BlockingQueue<QueueEntry> outQueue;

  private final DataSourceWrapper datasource;

  private final X509Cert caCert;

  private final AtomicBoolean stopMe;

  private final int totalAccount;

  private final String caSubjectName;

  private final AtomicBoolean endReached = new AtomicBoolean(false);

  private long lastProcessedId;

  private int caId;

  private ExecutorService executor;

  private Connection conn;

  private String selectCertSql;

  private DbType dbType;

  private HashAlgo certhashAlgo;

  private class Retriever implements Runnable {

    private PreparedStatement selectCertStmt;
    private boolean endReached;

    Retriever()
        throws DataAccessException {
      try {
        selectCertStmt = datasource.prepareStatement(conn, selectCertSql);
      } catch (DataAccessException ex) {
        datasource.returnConnection(conn);
        throw ex;
      }

    } // constructor

    @Override
    public void run() {
      while (!endReached && !stopMe.get()) {
        try {
          query();
        } catch (InterruptedException ex) {
          LOG.error("InterruptedException: {}", ex.getMessage());
        }
      }

      releaseResources(selectCertStmt, null);
      datasource.returnConnection(conn);
      selectCertStmt = null;
    } // method run

    private void query() throws InterruptedException {
      long startId = lastProcessedId + 1;
      DigestEntrySet result = new DigestEntrySet(startId);

      ResultSet rs = null;
      try {
        selectCertStmt.setLong(1, startId);

        rs = selectCertStmt.executeQuery();

        while (rs.next()) {
          long id = rs.getLong("ID");
          if (lastProcessedId < id) {
            lastProcessedId = id;
          }

          String hash = (dbType == DbType.XIPKI_OCSP_v4) ? rs.getString("HASH")
                        : (certhashAlgo == HashAlgo.SHA1)
                            ? rs.getString("SHA1")
                            : certhashAlgo.base64Hash(Base64.decodeFast(rs.getString("CERT")));

          BigInteger serial = new BigInteger(rs.getString("SN"), 16);
          boolean revoked = rs.getBoolean("REV");

          Integer revReason = null;
          Long revTime = null;
          Long revInvTime = null;

          if (revoked) {
            revReason = rs.getInt("RR");
            revTime = rs.getLong("RT");
            revInvTime = rs.getLong("RIT");
            if (revInvTime == 0) {
              revInvTime = null;
            }
          }

          DigestEntry cert = new DigestEntry(serial, revoked, revReason, revTime, revInvTime, hash);
          result.addEntry(new IdentifiedDigestEntry(cert, id));
        }
      } catch (Exception ex) {
        if (ex instanceof SQLException) {
          result.setException(datasource.translate(selectCertSql, (SQLException) ex));
        } else {
          result.setException(ex);
        }
      } finally {
        releaseResources(null, rs);
      }

      if (result.getEntries().isEmpty()) {
        endReached = true;
        outQueue.put(QueueEntry.END_OF_QUEUE);
      } else {
        outQueue.put(result);
      }
    } // method query

  } // class Retriever

  private RefDigestReader(DataSourceWrapper datasource, X509Cert caCert,
      int totalAccount, long minId, int numBlocksToRead, AtomicBoolean stopMe) {
    this.datasource = Args.notNull(datasource, "datasource");
    this.caCert = Args.notNull(caCert, "caCert");
    this.stopMe = Args.notNull(stopMe, "stopMe");
    this.totalAccount = totalAccount;
    this.caSubjectName = caCert.getSubjectText();
    this.lastProcessedId = minId - 1;
    this.outQueue = new ArrayBlockingQueue<>(numBlocksToRead);
  } // constructor

  private void init(DbType dbType, HashAlgo certhashAlgo, int caId, int numPerSelect) throws Exception {
    this.caId = caId;
    this.conn = datasource.getConnection();
    this.dbType = dbType;
    this.certhashAlgo = certhashAlgo;

    String coreSql;
    if (dbType == DbType.XIPKI_OCSP_v4) {
      String certHashAlgoInDb = datasource.getFirstStringValue(
          null, "DBSCHEMA", "VALUE2", "NAME='CERTHASH_ALGO'");
      if (certhashAlgo != HashAlgo.getInstance(certHashAlgoInDb)) {
        throw new IllegalArgumentException(
            "certHashAlgo in parameter (" + certhashAlgo + ") != in DB (" + certHashAlgoInDb + ")");
      }

      coreSql = StringUtil.concat("ID,SN,REV,RR,RT,RIT,HASH FROM CERT WHERE IID=",
          Integer.toString(caId), " AND ID>=?");
    } else {
      coreSql = StringUtil.concat("ID,SN,REV,RR,RT,RIT,", (certhashAlgo == HashAlgo.SHA1 ? "SHA1" : "CERT"),
          " FROM CERT WHERE CA_ID=", Integer.toString(caId), " AND ID>=?");
    }

    this.selectCertSql = datasource.buildSelectFirstSql(numPerSelect, "ID ASC", coreSql);

    try {
      executor = Executors.newFixedThreadPool(1);
      executor.execute(new Retriever());
    } catch (Exception ex) {
      LOG.error("could not initialize DigestReader", ex);
      close();

      throw new Exception("could not initialize me");
    }

  } // method init

  public int getCaId() {
    return caId;
  }

  public static RefDigestReader getInstance(
      DataSourceWrapper datasource, DbType dbType, HashAlgo certhashAlgo, int caId,
      int numBlocksToRead, int numPerSelect, AtomicBoolean stopMe)
      throws Exception {
    Args.notNull(datasource, "datasource");

    PreparedStatement stmt = null;
    ResultSet rs = null;
    String sql = null;

    X509Cert caCert;
    int totalAccount;
    long minId;

    try {
      String tblCa = (dbType == DbType.XIPKI_OCSP_v4) ? "ISSUER" : "CA";
      String colCaId = (dbType == DbType.XIPKI_OCSP_v4) ? "IID" : "CA_ID";

      sql = "SELECT CERT FROM " + tblCa + " WHERE ID=" + caId;
      stmt = datasource.prepareStatement(sql);

      rs = stmt.executeQuery();
      if (!rs.next()) {
        throw new IllegalArgumentException("no CA with id '" + caId + "' is available");
      }

      caCert = X509Util.parseCert(StringUtil.toUtf8Bytes(rs.getString("CERT")));
      rs.close();

      sql = "SELECT COUNT(*) FROM CERT WHERE " + colCaId + "=" + caId;
      rs = stmt.executeQuery(sql);

      totalAccount = rs.next() ? rs.getInt(1) : 0;
      rs.close();

      sql = "SELECT MIN(ID) FROM CERT WHERE " + colCaId + "=" + caId;
      rs = stmt.executeQuery(sql);
      minId = rs.next() ? rs.getLong(1) : 1;

      RefDigestReader reader = new RefDigestReader(datasource, caCert, totalAccount, minId, numBlocksToRead, stopMe);
      reader.init(dbType, certhashAlgo, caId, numPerSelect);
      return reader;
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method getInstance

  public X509Cert getCaCert() {
    return caCert;
  }

  public String getCaSubjectName() {
    return caSubjectName;
  }

  public int getTotalAccount() {
    return totalAccount;
  }

  public synchronized CertsBundle nextCerts() throws Exception {
    if (endReached.get() && outQueue.isEmpty()) {
      return null;
    }

    DigestEntrySet certSet;

    QueueEntry next = null;
    while (next == null) {
      if (stopMe.get()) {
        return null;
      }
      next = outQueue.poll(1, TimeUnit.SECONDS);
    }

    if (next instanceof QueueEntry.EndOfQueue) {
      endReached.set(true);
      return null;
    } else if (!(next instanceof DigestEntrySet)) {
      throw new IllegalStateException("unknown QueueEntry type: " + next.getClass().getName());
    }

    certSet = (DigestEntrySet) next;
    if (certSet.getException() != null) {
      throw certSet.getException();
    }

    List<BigInteger> serialNumbers = new LinkedList<>();
    Map<BigInteger, DigestEntry> certsMap = new HashMap<>();
    for (IdentifiedDigestEntry m : certSet.getEntries()) {
      BigInteger sn = m.getContent().getSerialNumber();
      serialNumbers.add(sn);
      certsMap.put(sn, m.getContent());
    }

    return new CertsBundle(certsMap, serialNumbers);
  } // method nextCerts

  @Override
  public void close() {
    if (executor != null) {
      executor.shutdownNow();
    }

    if (conn != null) {
      datasource.returnConnection(conn);
    }
  } // method close

  protected void releaseResources(PreparedStatement ps, ResultSet rs) {
    datasource.releaseResources(ps, rs);
  }

}
