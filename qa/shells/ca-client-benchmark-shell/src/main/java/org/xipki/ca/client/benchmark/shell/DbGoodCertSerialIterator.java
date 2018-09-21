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

package org.xipki.ca.client.benchmark.shell;

import java.math.BigInteger;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentLinkedDeque;

import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.Base64;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class DbGoodCertSerialIterator implements Iterator<BigInteger> {

  private static final int NUM_SQL_ENTRIES = 1000;

  private final String sqlNextSerials;

  private final DataSourceWrapper caDataSource;

  private final BigInteger caSerial;

  private final ConcurrentLinkedDeque<BigInteger> nextSerials = new ConcurrentLinkedDeque<>();

  private final int caId;

  private final long minId;

  private long nextStartId;

  private boolean noUnrevokedCerts;

  private BigInteger currentSerial;

  public DbGoodCertSerialIterator(Certificate caCert, DataSourceWrapper caDataSource)
      throws Exception {
    ParamUtil.requireNonNull("caCert", caCert);
    this.caDataSource = ParamUtil.requireNonNull("caDataSource", caDataSource);
    this.caSerial = caCert.getSerialNumber().getPositiveValue();

    this.sqlNextSerials = caDataSource.buildSelectFirstSql(NUM_SQL_ENTRIES, "ID",
            "ID,SN FROM CERT WHERE REV=0 AND CA_ID=? AND ID>=?");

    byte[] encodedCaCert = caCert.getEncoded();
    String sql = "SELECT ID,CERT FROM CA";
    Statement stmt = caDataSource.getConnection().createStatement();
    try {
      ResultSet rs = stmt.executeQuery(sql);
      int tmpCaId = -1;
      while (rs.next()) {
        String b64DbCert = rs.getString("CERT");
        byte[] dbCert = Base64.decodeFast(b64DbCert);
        if (Arrays.equals(encodedCaCert, dbCert)) {
          tmpCaId = rs.getInt("ID");
          break;
        }
      }
      rs.close();

      if (tmpCaId == -1) {
        throw new Exception("CA Certificate and database configuration does not match");
      }

      caId = tmpCaId;

      sql = "SELECT MIN(ID) FROM CERT WHERE REV=0 AND CA_ID=" + caId;
      rs = stmt.executeQuery(sql);
      rs.next();
      minId = rs.getLong(1);
      nextStartId = minId;
    } finally {
      caDataSource.releaseResources(stmt, null);
    }

    currentSerial = readNextNumber();
  } // constructor

  @Override
  public boolean hasNext() {
    return currentSerial != null;
  }

  @Override
  public synchronized BigInteger next() {
    BigInteger ret = currentSerial;
    this.currentSerial = readNextNumber();
    return ret;
  }

  private BigInteger readNextNumber() {
    BigInteger firstSerial = nextSerials.pollFirst();
    if (firstSerial != null) {
      return firstSerial;
    }

    if (noUnrevokedCerts) {
      return null;
    }

    String sql = sqlNextSerials;
    PreparedStatement stmt = null;
    ResultSet rs = null;

    int idx = 0;
    try {
      stmt = caDataSource.getConnection().prepareStatement(sql);
      stmt.setInt(1, caId);
      stmt.setLong(2, nextStartId);
      rs = stmt.executeQuery();
      while (rs.next()) {
        idx++;
        long id = rs.getLong("ID");
        if (id + 1 > nextStartId) {
          nextStartId = id + 1;
        }

        String serialStr = rs.getString("SN");
        BigInteger serial = new BigInteger(serialStr, 16);
        if (!caSerial.equals(serial)) {
          nextSerials.addLast(serial);
        }
      }
    } catch (SQLException ex) {
      DataAccessException daex = caDataSource.translate(sql, ex);
      throw new NoSuchElementException(daex.getMessage());
    } catch (DataAccessException ex) {
      throw new NoSuchElementException(ex.getMessage());
    } finally {
      caDataSource.releaseResources(stmt, rs);
    }

    if (idx < NUM_SQL_ENTRIES) {
      noUnrevokedCerts = true;
    }

    return nextSerials.pollFirst();
  }

}
