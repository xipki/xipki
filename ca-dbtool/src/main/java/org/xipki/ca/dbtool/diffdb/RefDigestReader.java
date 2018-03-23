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

package org.xipki.ca.dbtool.diffdb;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.dbtool.DbToolBase;
import org.xipki.common.EndOfQueue;
import org.xipki.common.QueueEntry;
import org.xipki.common.util.Base64;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class RefDigestReader {

  private static final Logger LOG = LoggerFactory.getLogger(RefDigestReader.class);

  private final BlockingQueue<QueueEntry> outQueue;

  private final DataSourceWrapper datasource;

  private final X509Certificate caCert;

  private final AtomicBoolean stopMe;

  private final int totalAccount;

  private final String caSubjectName;

  private final AtomicBoolean endReached = new AtomicBoolean(false);

  private long lastProcessedId;

  private int caId;

  private ExecutorService executor;

  private Retriever retriever;

  private Connection conn;

  private String selectCertSql;

  private DbControl dbControl;

  private HashAlgo certhashAlgo;

  private class Retriever implements Runnable {

    private PreparedStatement selectCertStmt;
    private boolean endReached;

    Retriever() throws DataAccessException {
      try {
        selectCertStmt = datasource.prepareStatement(conn, selectCertSql);
      } catch (DataAccessException ex) {
        datasource.returnConnection(conn);
        throw ex;
      }

    }

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
    }

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

          String hash;
          if (dbControl == DbControl.XIPKI_OCSP_v3) {
            hash = rs.getString("HASH");
          } else { // if (dbControl = DbControl.XIPKI_CA_v2) {
            if (certhashAlgo == HashAlgo.SHA1) {
              hash = rs.getString("SHA1");
            } else {
              String b64Cert = rs.getString("CERT");
              hash = certhashAlgo.base64Hash(Base64.decodeFast(b64Cert));
            }
          }
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
          ex = datasource.translate(selectCertSql, (SQLException) ex);
        }
        result.setException(ex);
      } finally {
        releaseResources(null, rs);
      }

      if (result.getEntries().isEmpty()) {
        endReached = true;
        outQueue.put(EndOfQueue.INSTANCE);
      } else {
        outQueue.put(result);
      }
    } // method query

  } // class XipkiDbRetriever

  private RefDigestReader(DataSourceWrapper datasource, X509Certificate caCert, int totalAccount,
      long minId, int numBlocksToRead, AtomicBoolean stopMe) throws Exception {
    this.datasource = ParamUtil.requireNonNull("datasource", datasource);
    this.caCert = ParamUtil.requireNonNull("caCert", caCert);
    this.stopMe = ParamUtil.requireNonNull("stopMe", stopMe);
    this.totalAccount = totalAccount;
    this.caSubjectName = X509Util.getRfc4519Name(caCert.getSubjectX500Principal());
    this.lastProcessedId = minId - 1;
    this.outQueue = new ArrayBlockingQueue<>(numBlocksToRead);
  } // constructor

  private void init(DbControl dbControl, HashAlgo certhashAlgo, int caId, int numPerSelect)
      throws Exception {
    this.caId = caId;
    this.conn = datasource.getConnection();
    this.dbControl = dbControl;
    this.certhashAlgo = certhashAlgo;

    String coreSql;
    if (dbControl == DbControl.XIPKI_OCSP_v3) {
      String certHashAlgoInDb = datasource.getFirstValue(
          null, "DBSCHEMA", "VALUE2", "NAME='CERTHASH_ALGO'", String.class);
      if (certhashAlgo != HashAlgo.getInstance(certHashAlgoInDb)) {
        throw new IllegalArgumentException(
            "certHashAlgo in parameter (" + certhashAlgo + ") != in DB (" + certHashAlgoInDb + ")");
      }

      coreSql = StringUtil.concat("ID,SN,REV,RR,RT,RIT,HASH FROM CERT WHERE IID=",
          Integer.toString(caId), " AND ID>=?");
    } else { // if (dbControl == DbControl.XIPKI_CA_v2) {
      coreSql = StringUtil.concat("ID,SN,REV,RR,RT,RIT,",
          (certhashAlgo == HashAlgo.SHA1 ? "SHA1" : "CERT"),
          " FROM CERT INNER JOIN CRAW ON CERT.CA_ID=", Integer.toString(caId),
          " AND CERT.ID>=? AND CERT.ID=CRAW.CID");
    }
    this.selectCertSql = datasource.buildSelectFirstSql(numPerSelect, "ID ASC", coreSql);

    try {
      retriever = new Retriever();
      executor = Executors.newFixedThreadPool(1);
      executor.execute(retriever);
    } catch (Exception ex) {
      LOG.error("could not initialize DigestReader", ex);
      close();

      throw new Exception("could not initialize me");
    }

  }

  public int getCaId() {
    return caId;
  }

  public static RefDigestReader getInstance(DataSourceWrapper datasource, DbControl dbControl,
      HashAlgo certhashAlgo, int caId, int numBlocksToRead, int numPerSelect, AtomicBoolean stopMe)
      throws Exception {
    ParamUtil.requireNonNull("datasource", datasource);

    Connection conn = datasource.getConnection();

    Statement stmt = null;
    ResultSet rs = null;
    String sql = null;

    X509Certificate caCert;
    int totalAccount;
    long minId;

    try {
      stmt = datasource.createStatement(conn);

      String tblCa;
      String colCaId;
      if (dbControl == DbControl.XIPKI_OCSP_v3) {
        tblCa = "ISSUER";
        colCaId = "IID";
      } else if (dbControl == DbControl.XIPKI_CA_v3) {
        tblCa = "CA";
        colCaId = "CA_ID";
      } else {
        throw new IllegalArgumentException("unknown dbControl " + dbControl);
      }

      sql = "SELECT CERT FROM " + tblCa + " WHERE ID=" + caId;
      rs = stmt.executeQuery(sql);
      if (!rs.next()) {
        throw new IllegalArgumentException("no CA with id '" + caId + "' is available");
      }

      caCert = X509Util.parseBase64EncodedCert(rs.getString("CERT"));
      rs.close();

      sql = "SELECT COUNT(*) FROM CERT WHERE " + colCaId + "=" + caId;
      rs = stmt.executeQuery(sql);

      totalAccount = rs.next() ? rs.getInt(1) : 0;
      rs.close();

      sql = "SELECT MIN(ID) FROM CERT WHERE " + colCaId + "=" + caId;
      rs = stmt.executeQuery(sql);
      minId = rs.next() ? rs.getLong(1) : 1;

      RefDigestReader reader = new RefDigestReader(datasource, caCert,
          totalAccount, minId, numBlocksToRead, stopMe);
      reader.init(dbControl, certhashAlgo, caId, numPerSelect);
      return reader;
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      DbToolBase.releaseResources(datasource, stmt, rs);
    }
  } // method getInstance

  public X509Certificate getCaCert() {
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

    if (next instanceof EndOfQueue) {
      endReached.set(true);
      return null;
    } else if (!(next instanceof DigestEntrySet)) {
      throw new RuntimeException("unknown QueueEntry type: " + next.getClass().getName());
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

  public void close() {
    if (executor != null) {
      executor.shutdownNow();
    }
  }

  protected void releaseResources(Statement ps, ResultSet rs) {
    DbToolBase.releaseResources(datasource, ps, rs);
  }

}
