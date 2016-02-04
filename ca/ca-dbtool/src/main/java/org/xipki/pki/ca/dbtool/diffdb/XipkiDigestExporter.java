/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.pki.ca.dbtool.diffdb;

import java.io.File;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.ProcessLog;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.dbtool.DbToolBase;
import org.xipki.pki.ca.dbtool.IDRange;
import org.xipki.pki.ca.dbtool.diffdb.io.CaEntry;
import org.xipki.pki.ca.dbtool.diffdb.io.CaEntryContainer;
import org.xipki.pki.ca.dbtool.diffdb.io.DbSchemaType;
import org.xipki.pki.ca.dbtool.diffdb.io.IdentifiedDbDigestEntry;
import org.xipki.pki.ca.dbtool.diffdb.io.XipkiDbControl;
import org.xipki.pki.ca.dbtool.diffdb.io.XipkiDigestExportReader;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XipkiDigestExporter extends DbToolBase implements DbDigestExporter {

  private static final Logger LOG = LoggerFactory.getLogger(XipkiDigestExporter.class);

  private final int numCertsPerSelect;

  private final XipkiDbControl dbControl;

  private final int numThreads;

  public XipkiDigestExporter(
      final DataSourceWrapper datasource,
      final String baseDir,
      final AtomicBoolean stopMe,
      final int numCertsPerSelect,
      final DbSchemaType dbSchemaType,
      final int numThreads)
  throws DataAccessException, IOException {
    super(datasource, baseDir, stopMe);
    if (numCertsPerSelect < 1) {
      throw new IllegalArgumentException("numCertsPerSelect could not be less than 1: "
          + numCertsPerSelect);
    }

    this.numCertsPerSelect = numCertsPerSelect;
    this.dbControl = new XipkiDbControl(dbSchemaType);

    // number of threads
    this.numThreads = Math.min(numThreads, datasource.getMaximumPoolSize() - 1);
    if (this.numThreads != numThreads) {
      LOG.info("adapted the numThreads from {} to {}", numThreads, this.numThreads);
    }
  }

  @Override
  public void digest()
  throws Exception {
    System.out.println("digesting database");

    final long total = getCount("CERT");
    ProcessLog processLog = new ProcessLog(total);

    Map<Integer, String> caIdDirMap = getCaIds();
    Set<CaEntry> caEntries = new HashSet<>(caIdDirMap.size());

    for (Integer caId : caIdDirMap.keySet()) {
      CaEntry caEntry = new CaEntry(caId, baseDir + File.separator + caIdDirMap.get(caId));
      caEntries.add(caEntry);
    }

    CaEntryContainer caEntryContainer = new CaEntryContainer(caEntries);
    XipkiDigestExportReader certsReader = new XipkiDigestExportReader(
        dataSource, dbControl, numThreads);

    Exception exception = null;
    try {
      doDigest(certsReader, processLog, caEntryContainer);
    } catch (Exception e) {
      // delete the temporary files
      deleteTmpFiles(baseDir, "tmp-");
      System.err.println("\ndigesting process has been cancelled due to error");
      LOG.error("Exception", e);
      exception = e;
    } finally {
      caEntryContainer.close();
      certsReader.stop();
    }

    if (exception == null) {
      System.out.println(" digested database");
    } else {
      throw exception;
    }
  } // method digest

  private Map<Integer, String> getCaIds()
  throws DataAccessException, IOException {
    Map<Integer, String> caIdDirMap = new HashMap<>();
    final String sql = dbControl.getCaSql();

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);
      while (rs.next()) {
        int id = rs.getInt("ID");
        String b64Cert = rs.getString("CERT");
        byte[] certBytes = Base64.decode(b64Cert);

        Certificate cert = Certificate.getInstance(certBytes);
        String commonName = X509Util.getCommonName(cert.getSubject());

        String fn = toAsciiFilename("ca-" + commonName);
        File caDir = new File(baseDir, fn);
        int i = 2;
        while (caDir.exists()) {
          caDir = new File(baseDir, fn + "." + (i++));
        }

        File caCertFile = new File(caDir, "ca.der");
        caDir.mkdirs();
        IoUtil.save(caCertFile, certBytes);

        caIdDirMap.put(id, caDir.getName());
      }
    } catch (SQLException e) {
      throw translate(sql, e);
    } finally {
      releaseResources(stmt, rs);
    }

    return caIdDirMap;
  } // method getCaIds

  private void doDigest(
      final XipkiDigestExportReader certsReader,
      final ProcessLog processLog,
      final CaEntryContainer caEntryContainer)
  throws Exception {
    int minCertId = (int) getMin("CERT", "ID");
    final int maxCertId = (int) getMax("CERT", "ID");
    System.out.println("digesting certificates from ID " + minCertId);
    processLog.printHeader();

    List<IDRange> idRanges = new ArrayList<>(numThreads);

    boolean interrupted = false;

    for (int i = minCertId; i <= maxCertId;) {

      if (stopMe.get()) {
        interrupted = true;
        break;
      }

      idRanges.clear();
      for (int j = 0; j < numThreads; j++) {
        int to = i + numCertsPerSelect - 1;
        idRanges.add(new IDRange(i, to));
        i = to + 1;
        if (i > maxCertId) {
          break; // break for (int j; ...)
        }
      }

      List<IdentifiedDbDigestEntry> certs = certsReader.readCerts(idRanges);
      for (IdentifiedDbDigestEntry cert : certs) {
        caEntryContainer.addDigestEntry(cert.getCaId().intValue(),
            cert.getId(), cert.getContent());
      }
      processLog.addNumProcessed(certs.size());
      processLog.printStatus();

      if (interrupted) {
        throw new InterruptedException("interrupted by the user");
      }
    }

    processLog.printTrailer();

    System.out.println(" digested " + processLog.getNumProcessed() + " certificates");
  } // method doDigest

  static String toAsciiFilename(
      final String filename) {
    final int n = filename.length();
    StringBuilder sb = new StringBuilder(n);
    for (int i = 0; i < n; i++) {
      char c = filename.charAt(i);
      if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
          || c == '.' || c == '_' || c == '-' || c == ' ') {
        sb.append(c);
      } else {
        sb.append('_');
      }
    }
    return sb.toString();
  }

}
