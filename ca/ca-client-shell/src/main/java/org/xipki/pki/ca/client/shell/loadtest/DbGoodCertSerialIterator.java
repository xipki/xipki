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

package org.xipki.pki.ca.client.shell.loadtest;

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
import org.xipki.common.util.Base64;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class DbGoodCertSerialIterator implements Iterator<BigInteger> {

    private static final int numSqlEntries = 1000;

    private final String sqlNextSerials;

    private final DataSourceWrapper caDataSource;

    private final BigInteger caSerial;

    private final ConcurrentLinkedDeque<BigInteger> nextSerials = new ConcurrentLinkedDeque<>();

    private final int caId;

    private final long minId;

    private long nextStartId;

    private boolean noUnrevokedCerts;

    private BigInteger currentSerial;

    public DbGoodCertSerialIterator(final Certificate caCert, final DataSourceWrapper caDataSource)
            throws Exception {
        ParamUtil.requireNonNull("caCert", caCert);
        this.caDataSource = ParamUtil.requireNonNull("caDataSource", caDataSource);
        this.caSerial = caCert.getSerialNumber().getPositiveValue();

        this.sqlNextSerials = caDataSource.buildSelectFirstSql(numSqlEntries, "ID",
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

        if (idx < numSqlEntries) {
            noUnrevokedCerts = true;
        }

        return nextSerials.pollFirst();
    }

}
