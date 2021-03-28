/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ocsp.server.store;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.CrlID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.asn1.CrlStreamParser;
import org.xipki.security.asn1.CrlStreamParser.RevokedCert;
import org.xipki.security.asn1.CrlStreamParser.RevokedCertsIterator;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.DateUtil;
import org.xipki.util.*;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.sql.*;
import java.util.Date;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.util.Args.min;
import static org.xipki.util.Args.notNull;

/**
 * Import CRLs to database.
 *
 * @author Lijun Liao
 * @since 2.2.0
 */

class ImportCrl {

  private static class CertInfo {
    private long id;

    private int crlId;

    private boolean revoked;

    private int revocationReason;

    private long revocationTime;

    private long invalidityTime;

    boolean isDifferent(RevokedCert revokedCert, int crlId) {
      if (this.crlId != crlId) {
        return true;
      }

      if (revoked) {
        if (revocationReason != revokedCert.getReason()) {
          return true;
        }

        if (revocationTime != revokedCert.getRevocationDate()) {
          return true;
        }

        return invalidityTime != revokedCert.getInvalidityDate();
      } else {
        return true;
      }
    }

  } // class CertInfo

  private static class CrlDirInfo {

    private final int crlId;

    private final String crlName;

    private final File crlDir;

    private final boolean updateMe;

    private String base64Sha1Fp;

    private CertRevocationInfo revocationinfo;

    private boolean shareCaWithOtherCrl = false;

    private final boolean deleteMe;

    CrlDirInfo(int crlId, String crlName, File crlDir, boolean updateMe, boolean deleteMe) {
      this.crlId = crlId;
      this.crlName = crlName;
      this.crlDir = crlDir;
      this.updateMe = updateMe;
      this.deleteMe = deleteMe;
    }

  } // class CrlDirInfo

  private static class CertWrapper {

    private final X509Cert cert;

    private final X500Name subject;

    private final String base64Sha1Fp;

    private final String base64Encoded;

    private final byte[] subjectKeyIdentifier;

    private Integer databaseId;

    CertWrapper(X509Cert cert) {
      this.cert = cert;
      this.subject = cert.getSubject();
      byte[] encoded = cert.getEncoded();
      this.base64Sha1Fp = HashAlgo.SHA1.base64Hash(encoded);
      this.base64Encoded = Base64.encodeToString(encoded);
      this.subjectKeyIdentifier = cert.getSubjectKeyId();
    }

  } // class CertWrapper

  private static class ImportCrlException extends Exception {

    private static final long serialVersionUID = 1L;

    public ImportCrlException(String message, Throwable cause) {
      super(message, cause);
    }

    public ImportCrlException(String message) {
      super(message);
    }

  } // class ImportCrlException

  private static final Logger LOG = LoggerFactory.getLogger(ImportCrl.class);

  private static final String KEY_CA_REVOCATION_TIME = "ca.revocation.time";

  private static final String KEY_CA_INVALIDITY_TIME = "ca.invalidity.time";

  private static final String SQL_UPDATE_CRL_INFO
      = "UPDATE CRL_INFO SET INFO=? WHERE ID=?";

  private static final String SQL_INSERT_CRL_INFO
      = "INSERT INTO CRL_INFO (ID,NAME,INFO) VALUES(?,?,?)";

  private static final String SQL_UPDATE_CERT_REV
      = "UPDATE CERT SET REV=?,RR=?,RT=?,RIT=?,LUPDATE=?,CRL_ID=? WHERE ID=?";

  private static final String SQL_INSERT_CERT_REV
      = "INSERT INTO CERT (ID,IID,SN,REV,RR,RT,RIT,LUPDATE,CRL_ID) VALUES(?,?,?,?,?,?,?,?,?)";

  private static final String SQL_DELETE_CERT = "DELETE FROM CERT WHERE IID=? AND SN=?";

  private static final String SQL_UPDATE_CERT_LUPDATE = "UPDATE CERT SET LUPDATE=? WHERE ID=?";

  private static final String SQL_UPDATE_CERT
      = "UPDATE CERT SET LUPDATE=?,NBEFORE=?,NAFTER=?,CRL_ID=?,HASH=? WHERE ID=?";

  private static final String SQL_INSERT_CERT
      = "INSERT INTO CERT (ID,IID,SN,REV,RR,RT,RIT,LUPDATE,NBEFORE,NAFTER,CRL_ID,HASH) "
        + "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)";

  private static final String CORE_SQL_SELECT_ID_CERT
      = "ID,REV,RR,RT,RIT,CRL_ID FROM CERT WHERE IID=? AND SN=?";

  private final String basedir;

  private final String sqlSelectIdCert;

  private final DataSourceWrapper datasource;

  private final HashAlgo certhashAlgo;

  private final int sqlBatchCommit;

  private final boolean ignoreExpiredCrls;

  private PreparedStatement psDeleteCert;

  private PreparedStatement psInsertCert;

  private PreparedStatement psInsertCertRev;

  private PreparedStatement psSelectIdCert;

  private PreparedStatement psUpdateCert;

  private PreparedStatement psUpdateCertRev;

  private PreparedStatement psUpdateCertLastupdate;

  private final AtomicInteger cachedIssuerId = new AtomicInteger(0);

  public ImportCrl(DataSourceWrapper datasource, String basedir, int sqlBatchCommit,
      boolean ignoreExpiredCrls)
          throws DataAccessException, NoSuchAlgorithmException {
    this.sqlBatchCommit = min(sqlBatchCommit, "sqlBatchCommit", 1);
    this.ignoreExpiredCrls = ignoreExpiredCrls;
    this.datasource = notNull(datasource, "datasource");
    this.basedir = notNull(basedir, "basedir");
    this.certhashAlgo = DbCertStatusStore.getCertHashAlgo(datasource);

    LOG.info("UPDATE_CERTSTORE");
    this.sqlSelectIdCert = datasource.buildSelectFirstSql(1, CORE_SQL_SELECT_ID_CERT);
  }

  public boolean importCrlToOcspDb() {
    File[] crlDirs = new File(basedir).listFiles();
    if (crlDirs == null) {
      crlDirs = new File[0];
    }
    // parse the CRL directories except the CRL
    Set<CrlDirInfo> crlDirInfos = new HashSet<>();

    for (File crlDir : crlDirs) {
      String crlName = getCrlNameFromDir(crlDir);
      if (StringUtil.isBlank(crlName)) {
        continue;
      }

      // make sure that the crl id is not 0.
      int crlId = getCrlIdFromName(crlName);
      if (crlId == 0) {
        LOG.error("Please rename the directory {}", crlDir.getPath());
        return false;
      }

      // make sure that no two directories have the same crl id.
      CrlDirInfo parsedInfo = null;
      for (CrlDirInfo m : crlDirInfos) {
        if (m.crlId == crlId) {
          parsedInfo = m;
        }
      }

      if (parsedInfo != null) {
        LOG.error("Please rename one of the directories {} or {}", crlDir.getPath(),
            parsedInfo.crlDir.getPath());
        return false;
      }

      File updatemeFile = new File(crlDir, "UPDATEME");
      if (!updatemeFile.exists()) {
        // no change
        continue;
      }

      File caCertFile = new File(crlDir, "ca.crt");
      if (!caCertFile.exists()) {
        LOG.error("CA certificate file {} does not exist", caCertFile.getPath());
        return false;
      }

      CertRevocationInfo caRevInfo = null;
      File revFile = new File(crlDir, "REVOCATION");
      if (revFile.exists()) {
        Properties props = new Properties();
        try {
          try (InputStream is = Files.newInputStream(revFile.toPath())) {
            props.load(is);
          }
        } catch (IOException ex) {
          LOG.error("error reading " + revFile.getPath(), ex);
          return false;
        }

        String str = props.getProperty(KEY_CA_REVOCATION_TIME);
        if (StringUtil.isNotBlank(str)) {
          Date revocationTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
          Date invalidityTime = null;

          str = props.getProperty(KEY_CA_INVALIDITY_TIME);
          if (StringUtil.isNotBlank(str)) {
            invalidityTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
          }

          caRevInfo = new CertRevocationInfo(
                          CrlReason.UNSPECIFIED, revocationTime, invalidityTime);
        }
      }

      String base64Sha1Fp;
      try {
        byte[] derCertBytes = X509Util.toDerEncoded(IoUtil.read(caCertFile));
        base64Sha1Fp = HashAlgo.SHA1.base64Hash(derCertBytes);
      } catch (IOException ex) {
        LOG.error("error reading " + caCertFile.getPath(), ex);
        return false;
      }

      boolean updateMe = new File(crlDir, "UPDATEME").exists();
      boolean deleteMe = new File(crlDir, "DELETEME").exists();
      CrlDirInfo crlDirInfo = new CrlDirInfo(crlId, crlName, crlDir, updateMe, deleteMe);
      crlDirInfo.base64Sha1Fp = base64Sha1Fp;
      crlDirInfo.revocationinfo = caRevInfo;
      crlDirInfos.add(crlDirInfo);
    }

    // pre processing
    for (CrlDirInfo m : crlDirInfos) {
      File crlDir = m.crlDir;
      if (m.deleteMe || m.revocationinfo != null) {
        // make sure that CA to be deleted or revoked CA is not specified in two different folders
        for (CrlDirInfo n : crlDirInfos) {
          if (m != n && m.base64Sha1Fp.equals(n.base64Sha1Fp)) {
            LOG.error("{} and {} specify duplicatedly a revoked CA certificate.",
                crlDir.getPath(), n.crlDir.getPath());
            return false;
          }
        }
      } else {
        // make sure that unrevoked CA to be updated has the file ca.crl.
        if (m.updateMe) {
          File crlFile = new File(crlDir, "ca.crl");
          if (!(crlFile.exists() && crlFile.isFile())) {
            LOG.error("{} has UPDATEME but no ca.crl", crlDir.getPath());
            return false;
          }
        }
      }

      boolean shareCaWithOtherCrl = false;
      for (CrlDirInfo n : crlDirInfos) {
        if (m != n && m.base64Sha1Fp.equals(n.base64Sha1Fp)) {
          shareCaWithOtherCrl = true;
          break;
        }
      }
      m.shareCaWithOtherCrl = shareCaWithOtherCrl;
    }

    Connection conn = null;
    boolean autoCommitChanged = false;
    try {
      conn = datasource.getConnection();

      // disable the autoCommit for better performance
      boolean origAutocommit = conn.getAutoCommit();
      if (origAutocommit) {
        conn.setAutoCommit(false);
        autoCommitChanged = true;
      }

      psDeleteCert = datasource.prepareStatement(conn, SQL_DELETE_CERT);
      psInsertCert = datasource.prepareStatement(conn, SQL_INSERT_CERT);
      psInsertCertRev = datasource.prepareStatement(conn, SQL_INSERT_CERT_REV);
      psSelectIdCert = datasource.prepareStatement(conn, sqlSelectIdCert);
      psUpdateCert = datasource.prepareStatement(conn, SQL_UPDATE_CERT);
      psUpdateCertRev = datasource.prepareStatement(conn, SQL_UPDATE_CERT_REV);
      psUpdateCertLastupdate = datasource.prepareStatement(conn, SQL_UPDATE_CERT_LUPDATE);

      for (CrlDirInfo crlDirInfo : crlDirInfos) {
        if (crlDirInfo.updateMe) {
          importCrl(conn, crlDirInfo);
        }
      }

      return true;
    } catch (Throwable th) {
      LogUtil.error(LOG, th, "could not import CRL to OCSP database");
    } finally {
      try {
        commit(conn);
      } catch (Throwable th) {
        LOG.error("could not import CRL to OCSP database (Connection.commit)");
      }

      if (autoCommitChanged) {
        // change the autoCommit back to original value.
        try {
          conn.setAutoCommit(true);
        } catch (SQLException ex) {
          LOG.error("could not import CRL to OCSP database (Connection.setAutoCommit)");
        }
      }

      releaseResources(psDeleteCert, null);
      releaseResources(psInsertCert, null);
      releaseResources(psInsertCertRev, null);
      releaseResources(psSelectIdCert, null);
      releaseResources(psUpdateCert, null);
      releaseResources(psUpdateCertRev, null);
      releaseResources(psUpdateCertLastupdate, null);

      if (conn != null) {
        datasource.returnConnection(conn);
      }
    }

    return false;
  } // method importCrlToOcspDb

  private void importCrl(Connection conn, CrlDirInfo crlDirInfo) {
    // Delete the files UPDATE.SUCC and UPDATE.FAIL
    IoUtil.deleteFile(new File(crlDirInfo.crlDir, "UPDATEME.SUCC"));
    IoUtil.deleteFile(new File(crlDirInfo.crlDir, "UPDATEME.FAIL"));

    long startTimeSec = System.currentTimeMillis() / 1000;

    int id = crlDirInfo.crlId;
    String crlName = crlDirInfo.crlName;
    File crlDir = crlDirInfo.crlDir;

    boolean updateSucc = false;
    CertWrapper caCert = null;

    try {
      LOG.info("Importing CRL (id={}, name={}) in the folder {}",
          id, crlName, crlDir.getPath());

      File caCertFile = new File(crlDirInfo.crlDir, "ca.crt");
      try {
        X509Cert cert = X509Util.parseCert(caCertFile);
        caCert = new CertWrapper(cert);
      } catch (CertificateException ex) {
        LOG.error("could not parse CA certificate " + caCertFile.getPath(), ex);
        return;
      }

      CrlStreamParser crl = null;
      CrlInfo crlInfo = null;

      if (!crlDirInfo.deleteMe & crlDirInfo.revocationinfo == null) {
        crl = new CrlStreamParser(new File(crlDir, "ca.crl"));
        Date now = new Date();
        if (crl.getNextUpdate() != null && crl.getNextUpdate().before(now)) {
          if (ignoreExpiredCrls) {
            LOG.error("CRL is expired, ignore it");
            return;
          }
        } else if (crl.getThisUpdate().after(now)) {
          LOG.error("CRL is not valid yet, ignore it");
          return;
        }

        X500Name issuer = crl.getIssuer();

        X509Cert crlSignerCert;
        if (caCert.subject.equals(issuer)) {
          crlSignerCert = caCert.cert;
        } else {
          X509Cert crlIssuerCert = null;
          File issuerCertFile = new File(crlDir, "issuer.crt");
          if (issuerCertFile.exists()) {
            crlIssuerCert = parseCert(issuerCertFile);
          }

          if (crlIssuerCert == null) {
            LOG.error("issuerCert may not be null");
            return;
          }

          if (!crlIssuerCert.getSubject().equals(issuer)) {
            LOG.error("issuerCert and CRL do not match");
            return;
          }

          crlSignerCert = crlIssuerCert;
        }

        if (crl.getCrlNumber() == null) {
          LOG.error("crlNumber is not specified, ignore the CRL");
          return;
        }

        LOG.info("The CRL is a {}", crl.isDeltaCrl() ? "DeltaCRL" : "FullCRL");

        // Construct CrlID
        ASN1EncodableVector vec = new ASN1EncodableVector();
        File urlFile = new File(basedir, "crl.url");
        if (urlFile.exists()) {
          String crlUrl = StringUtil.toUtf8String(IoUtil.read(urlFile)).trim();
          if (StringUtil.isNotBlank(crlUrl)) {
            vec.add(new DERTaggedObject(true, 0, new DERIA5String(crlUrl, true)));
          }
        }

        vec.add(new DERTaggedObject(true, 1, new ASN1Integer(crl.getCrlNumber())));
        vec.add(new DERTaggedObject(true, 2,
                    new ASN1GeneralizedTime(crl.getThisUpdate())));
        CrlID crlId = CrlID.getInstance(new DERSequence(vec));

        BigInteger crlNumber = crl.getCrlNumber();
        BigInteger baseCrlNumber = crl.getBaseCrlNumber();

        String str = datasource.getFirstValue(
                      conn, "CRL_INFO", "INFO", "ID='" + id + "'", String.class);
        boolean addNew = str == null;

        if (addNew) {
          if (crl.isDeltaCrl()) {
            LOG.error("Given CRL is a DeltaCRL for the full CRL with number {}, "
                + "please import this full CRL first.", baseCrlNumber);
            return;
          }
        } else {
          CrlInfo oldCrlInfo = new CrlInfo(str);
          if (crlNumber.compareTo(oldCrlInfo.getCrlNumber()) < 0) {
            // It is permitted if the CRL number equals to the one in Database,
            // which enables the resume of importing process if error occurred.
            LOG.error("Given CRL is older than existing CRL, ignore it");
            return;
          }

          if (crl.isDeltaCrl()) {
            BigInteger lastFullCrlNumber = oldCrlInfo.getBaseCrlNumber();
            if (lastFullCrlNumber == null) {
              lastFullCrlNumber = oldCrlInfo.getCrlNumber();
            }

            if (!baseCrlNumber.equals(lastFullCrlNumber)) {
              LOG.error(
                  "Given CRL is a deltaCRL for the full CRL with number {}, "
                  + "please import this full CRL first.", crlNumber);
              return;
            }
          }
        }

        // Verify the signature
        if (!crl.verifySignature(crlSignerCert.getSubjectPublicKeyInfo())) {
          LOG.error("signature of CRL is invalid, ignore the CRL");
          return;
        }

        crlInfo = new CrlInfo(crlNumber, baseCrlNumber,
            crl.getThisUpdate(), crl.getNextUpdate(), crlId);
      }

      if (crlDirInfo.deleteMe) {
        deleteCa(conn, crlDirInfo, caCert);
      } else {
        importCa(conn, crlDirInfo, caCert);
      }

      commit(conn);

      if (crl == null) {
        LOG.info("Ignored CRL (name={}) in the folder {}: CA is revoked",
            crlName, crlDir.getPath());
      } else {
        importCrlInfo(conn, id, crlName, crlInfo,
            crlDirInfo.shareCaWithOtherCrl, caCert.base64Sha1Fp);
        commit(conn);

        importCrlRevokedCertificates(conn, id, caCert, crl, crlDir, startTimeSec);
        commit(conn);

        if (!crl.isDeltaCrl()) {
          deleteEntriesNotUpdatedSince(conn, id, startTimeSec);
          commit(conn);
        }
      }

      updateSucc = true;
      LOG.info("Imported CRL (id={}) in the folder {}", id, crlDir.getPath());
    } catch (Throwable th) {
      LOG.error(String.format(
          "Importing CRL (id=%s) in the folder %s FAILED", id, crlDir.getPath()), th);
    } finally {
      try {
        commit(conn);
      } catch (Throwable th) {
        LOG.error(String.format(
            "Importing CRL (id=%s) in the folder %s FAILED (Connect.commit)",
            id, crlDir.getPath()), th);
      }

      File updatemeFile = new File(crlDirInfo.crlDir, "UPDATEME");
      updatemeFile.setLastModified(System.currentTimeMillis());
      updatemeFile.renameTo(new File(updatemeFile.getPath() + (updateSucc ? ".SUCC" : ".FAIL")));
      if (!updateSucc && caCert != null) {
        if (!crlDirInfo.shareCaWithOtherCrl && caCert.databaseId != null) {
          // try to delete the issuer if there is not certificate associated with it
          try {
            datasource.deleteFromTableWithException(conn, "ISSUER", "ID", caCert.databaseId);
          } catch (Throwable th) {
            LOG.warn("error deleting from table ISSUER for ID {}", caCert.databaseId);
          }
        }
      }
    }
  } // method importCrl

  /**
   * Delete CA.
   *
   * @param conn The database connection.
   * @param crlDirInfo CRL directory information.
   * @throws DataAccessException
   *         If database exception occurs.
   */
  private void deleteCa(Connection conn, CrlDirInfo crlDirInfo, CertWrapper caCert)
      throws DataAccessException {
    Integer issuerId = datasource.getFirstValue(conn, "ISSUER", "ID",
        "S1C='" + caCert.base64Sha1Fp + "'", Integer.class);
    if (issuerId == null) {
      LOG.info("No issuer for CRL {} in the folder {} found in database",
          crlDirInfo.crlId, crlDirInfo.crlDir.getPath());
      return;
    }

    // Delete the table CERT first
    datasource.deleteFromTable(conn, "CERT", "IID", issuerId);

    // Delete the table ISSUER
    datasource.deleteFromTable(conn, "ISSUER", "ID", issuerId);
  } // method deleteCa

  /**
   * Import the CA certificate with revocation information.
   *
   * @param conn The database connection.
   * @param crlDirInfo CRL directory information.
   * @throws DataAccessException
   *         If database exception occurs.
   */
  private void importCa(Connection conn, CrlDirInfo crlDirInfo, CertWrapper caCert)
      throws DataAccessException {
    CertRevocationInfo revInfo = crlDirInfo.revocationinfo;

    Integer issuerId = datasource.getFirstValue(conn, "ISSUER", "ID",
        "S1C='" + caCert.base64Sha1Fp + "'", Integer.class);

    PreparedStatement ps = null;
    String sql = null;

    try {
      int offset = 1;
      if (issuerId == null) {
        // issuer not exists
        int maxId = (int) datasource.getMax(conn, "ISSUER", "ID");
        issuerId = Math.max(cachedIssuerId.get(), maxId) + 1;
        cachedIssuerId.set(issuerId);

        sql = "INSERT INTO ISSUER (ID,SUBJECT,NBEFORE,NAFTER,S1C,CERT,REV_INFO)"
            + " VALUES(?,?,?,?,?,?,?)";
        ps = datasource.prepareStatement(conn, sql);
        String subject = X509Util.getRfc4519Name(caCert.subject);

        ps.setInt(offset++, issuerId);
        ps.setString(offset++, subject);
        ps.setLong(offset++, caCert.cert.getNotBefore().getTime() / 1000);
        ps.setLong(offset++, caCert.cert.getNotAfter().getTime() / 1000);
        ps.setString(offset++, caCert.base64Sha1Fp);
        ps.setString(offset++, caCert.base64Encoded);
        ps.setString(offset, revInfo == null ? null : revInfo.getEncoded());
      } else {
        // issuer exists
        sql = "UPDATE ISSUER SET REV_INFO=? WHERE ID=?";
        ps = datasource.prepareStatement(conn, sql);
        ps.setString(offset++, revInfo == null ? null : revInfo.getEncoded());
        ps.setInt(offset, issuerId);
      }

      ps.executeUpdate();

      caCert.databaseId = issuerId;
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      releaseResources(ps, null);
    }
  } // method importCa

  private void importCrlInfo(Connection conn, int id, String name, CrlInfo crlInfo,
      boolean shareCaWithOtherCrl, String sha1FpOfIssuerCert)
          throws DataAccessException {
    boolean exists = datasource.columnExists(conn, "CRL_INFO", "ID", id);

    PreparedStatement ps = null;
    String sql = null;

    try {
      // issuer exists
      if (exists) {
        sql = SQL_UPDATE_CRL_INFO;
        ps = datasource.prepareStatement(conn, sql);
        ps.setString(1, crlInfo.getEncoded());
        ps.setInt(2, id);
      } else {
        sql = SQL_INSERT_CRL_INFO;
        ps = datasource.prepareStatement(conn, sql);
        ps.setInt(1, id);
        ps.setString(2, name);
        ps.setString(3, crlInfo.getEncoded());
      }

      ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      releaseResources(ps, null);
    }

    // If one issuer has more than one CRLs, the CRL_ID is set to 0,
    // otherwise set it to the id
    try {
      sql = "UPDATE ISSUER SET CRL_ID=? WHERE S1C=?";
      ps = datasource.prepareStatement(conn, sql);
      if (shareCaWithOtherCrl) {
        // clear the CRL_ID
        ps.setNull(1, Types.INTEGER);
      } else {
        // update the CRL_ID
        ps.setInt(1, id);
      }
      ps.setString(2, sha1FpOfIssuerCert);
      ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      releaseResources(ps, null);
    }
  } // method importCrlInfo

  private void importCrlRevokedCertificates(Connection conn, int crlInfoId, CertWrapper caCert,
      CrlStreamParser crl, File crlDir, long startTimeSec)
          throws DataAccessException, ImportCrlException, IOException {
    int caId = caCert.databaseId;
    AtomicLong maxId = new AtomicLong(datasource.getMax(conn, "CERT", "ID"));

    boolean isDeltaCrl = crl.isDeltaCrl();

    // import the revoked information
    try (RevokedCertsIterator revokedCertList = crl.revokedCertificates()) {
      int num = 0;
      while (revokedCertList.hasNext()) {
        num++;

        // If the system time is adjusted to a previous time point during the
        // import process, System.currentTime...() may be before startTime.
        // Since all entries in the database whose Last-Update is before
        // startTime will be deleted, we must ensure that the Last-Update is
        // not before startTime.
        long updateTimeSec = Math.max(System.currentTimeMillis() / 1000, startTimeSec);

        RevokedCert revCert = revokedCertList.next();
        BigInteger serial = revCert.getSerialNumber();
        long rt = revCert.getRevocationDate();
        long rit = revCert.getInvalidityDate();
        int reason = revCert.getReason();
        X500Name issuer = revCert.getCertificateIssuer();
        if (issuer != null && !issuer.equals(caCert.subject)) {
          throw new ImportCrlException("invalid CRLEntry for certificate number " + serial);
        }

        String sql = null;
        try {
          if (reason == CrlReason.REMOVE_FROM_CRL.getCode()) {
            if (isDeltaCrl) {
              // delete the entry
              sql = SQL_DELETE_CERT;
              psDeleteCert.setInt(1, caId);
              psDeleteCert.setString(2, serial.toString(16));
              psDeleteCert.executeUpdate();
            } else {
              LOG.warn("ignore CRL entry with reason removeFromCRL in non-Delta CRL");
            }
            continue;
          }

          CertInfo existingCertInfo = getCertInfo(caId, serial);
          PreparedStatement ps;

          if (existingCertInfo == null) {
            sql = SQL_INSERT_CERT_REV;
            long id = maxId.incrementAndGet();
            ps = psInsertCertRev;
            int offset = 1;

            ps.setLong(offset++, id);
            ps.setInt(offset++, caId);
            ps.setString(offset++, serial.toString(16));
            ps.setInt(offset++, 1);
            ps.setInt(offset++, reason);
            ps.setLong(offset++, rt);
            if (rit != 0) {
              ps.setLong(offset++, rit);
            } else {
              ps.setNull(offset++, Types.BIGINT);
            }
            ps.setLong(offset++, updateTimeSec);
            ps.setInt(offset, crlInfoId);
          } else {
            if (existingCertInfo.isDifferent(revCert, crlInfoId)) {
              sql = SQL_UPDATE_CERT_REV;
              ps = psUpdateCertRev;
              int offset = 1;

              ps.setInt(offset++, 1);
              ps.setInt(offset++, reason);
              ps.setLong(offset++, rt);
              if (rit != 0) {
                ps.setLong(offset++, rit);
              } else {
                ps.setNull(offset++, Types.BIGINT);
              }
              ps.setLong(offset++, updateTimeSec);
              ps.setInt(offset++, crlInfoId);
              ps.setLong(offset, existingCertInfo.id);
            } else {
              sql = SQL_UPDATE_CERT_LUPDATE;
              ps = psUpdateCertLastupdate;
              ps.setLong(1, updateTimeSec);
              ps.setLong(2, existingCertInfo.id);
            }
          }

          ps.executeUpdate();

          if (num % sqlBatchCommit == 0) {
            commit(conn);
          }
        } catch (SQLException ex) {
          throw datasource.translate(sql, ex);
        }
      }

      LOG.info("imported {} revoked certificates", num);
    }

    commit(conn);

    // import the certificates
    // cert dirs
    File certsDir = new File(crlDir, "certs");

    if (!certsDir.exists()) {
      LOG.info("the folder {} does not exist, ignore it", certsDir.getPath());
      return;
    }

    if (!certsDir.isDirectory()) {
      LOG.warn("the path {} does not point to a folder, ignore it", certsDir.getPath());
      return;
    }

    if (!certsDir.canRead()) {
      LOG.warn("the folder {} may not be read, ignore it", certsDir.getPath());
      return;
    }

    // import certificates
    File[] certFiles = certsDir.listFiles(
            (dir, name) -> name.endsWith(".der") || name.endsWith(".crt") || name.endsWith(".pem"));

    if (certFiles != null && certFiles.length > 0) {
      int num = 0;
      for (File certFile : certFiles) {
        num++;
        X509Cert cert;
        try {
          cert = X509Util.parseCert(certFile);
        } catch (IllegalArgumentException | IOException | CertificateException ex) {
          LOG.warn("could not parse certificate {}, ignore it", certFile.getPath());
          continue;
        }

        String certLogId = "(file " + certFile.getName() + ")";
        addCertificate(maxId, crlInfoId, caCert, cert, certLogId);

        if (num >= sqlBatchCommit) {
          num = 0;
          commit(conn);
        }
      }

      commit(conn);
    }

    // import certificate serial numbers
    File[] serialNumbersFiles = certsDir.listFiles((dir, name) -> name.endsWith(".serials"));

    if (serialNumbersFiles != null && serialNumbersFiles.length > 0) {
      int num = 0;
      for (File serialNumbersFile : serialNumbersFiles) {
        num++;
        try (BufferedReader reader = new BufferedReader(new FileReader(serialNumbersFile))) {
          String line;
          while ((line = reader.readLine()) != null) {
            BigInteger serialNumber = new BigInteger(line.trim(), 16);
            addCertificateBySerialNumber(maxId, caId, crlInfoId, serialNumber);
          }
        } catch (IOException ex) {
          LOG.warn("could not import certificates by serial numbers from file {}, ignore it",
              serialNumbersFile.getPath());
          continue;
        }

        if (num >= sqlBatchCommit) {
          num = 0;
          commit(conn);
        }
      }

      commit(conn);
    }
  } // method importCrlRevokedCertificates

  private static X509Cert parseCert(File certFile)
      throws ImportCrlException {
    try {
      return X509Util.parseCert(certFile);
    } catch (CertificateException | IOException ex) {
      throw new ImportCrlException("could not parse X.509 certificate from file "
          + certFile + ": " + ex.getMessage(), ex);
    }
  } // method parseCert

  private CertInfo getCertInfo(int caId, BigInteger serialNumber)
      throws DataAccessException {
    ResultSet rs = null;
    try {
      psSelectIdCert.setInt(1, caId);
      psSelectIdCert.setString(2, serialNumber.toString(16));
      rs = psSelectIdCert.executeQuery();
      if (!rs.next()) {
        return null;
      }

      CertInfo ci = new CertInfo();
      ci.crlId = rs.getInt("CRL_ID");
      ci.id = rs.getLong("ID");
      ci.invalidityTime = rs.getLong("RIT");
      ci.revocationReason = rs.getInt("RR");
      ci.revocationTime = rs.getLong("RT");
      ci.revoked = rs.getBoolean("REV");

      return ci;
    } catch (SQLException ex) {
      throw datasource.translate(sqlSelectIdCert, ex);
    } finally {
      releaseResources(null, rs);
    }
  } // method getCertInfo

  private void addCertificate(AtomicLong maxId, int crlInfoId, CertWrapper caCert, X509Cert cert,
      String certLogId)
          throws DataAccessException {
    // CHECKSTYLE:SKIP
    int caId = caCert.databaseId;

    // not issued by the given issuer
    if (!caCert.subject.equals(cert.getIssuer())) {
      LOG.warn("certificate {} is not issued by the given CA, ignore it", certLogId);
      return;
    }

    // we don't use the binary read from file, since it may contains redundant ending bytes.
    byte[] encodedCert = cert.getEncoded();
    String b64CertHash = certhashAlgo.base64Hash(encodedCert);

    if (caCert.subjectKeyIdentifier != null) {
      byte[] aki = cert.getAuthorityKeyId();

      if (aki == null || !Arrays.equals(caCert.subjectKeyIdentifier, aki)) {
        LOG.warn("certificate {} is not issued by the given CA, ignore it", certLogId);
        return;
      }
    } // end if

    LOG.info("Importing certificate {}", certLogId);
    CertInfo existingCertInfo = getCertInfo(caId, cert.getSerialNumber());

    PreparedStatement ps;
    String sql = null;

    try {
      if (existingCertInfo == null) {
        sql = SQL_INSERT_CERT;
        ps = psInsertCert;

        long id = maxId.incrementAndGet();
        int offset = 1;
        ps.setLong(offset++, id);
        // ISSUER ID IID
        ps.setInt(offset++, caId);
        // serial number SN
        ps.setString(offset++, cert.getSerialNumber().toString(16));
        // whether revoked REV
        ps.setInt(offset++, 0);
        // revocation reason RR
        ps.setNull(offset++, Types.SMALLINT);
        // revocation time RT
        ps.setNull(offset++, Types.BIGINT);
        ps.setNull(offset++, Types.BIGINT);

        // last update LUPDATE
        ps.setLong(offset++, System.currentTimeMillis() / 1000);

        TBSCertificate tbsCert = cert.toBcCert().toASN1Structure().getTBSCertificate();
        // not before NBEFORE
        ps.setLong(offset++, tbsCert.getStartDate().getDate().getTime() / 1000);
        // not after NAFTER
        ps.setLong(offset++, tbsCert.getEndDate().getDate().getTime() / 1000);
        ps.setInt(offset++, crlInfoId);

        ps.setString(offset, b64CertHash);
      } else {
        if (existingCertInfo.revoked || existingCertInfo.crlId != crlInfoId) {
          sql = SQL_UPDATE_CERT;
          ps = psUpdateCert;

          int offset = 1;
          // last update LUPDATE
          ps.setLong(offset++, System.currentTimeMillis() / 1000);

          TBSCertificate tbsCert = cert.toBcCert().toASN1Structure().getTBSCertificate();
          // not before NBEFORE
          ps.setLong(offset++, tbsCert.getStartDate().getDate().getTime() / 1000);
          // not after NAFTER
          ps.setLong(offset++, tbsCert.getEndDate().getDate().getTime() / 1000);
          ps.setInt(offset++, crlInfoId);

          ps.setString(offset++, b64CertHash);
          ps.setLong(offset, existingCertInfo.id);
        } else {
          sql = SQL_UPDATE_CERT_LUPDATE;
          ps = psUpdateCertLastupdate;

          // last update LUPDATE
          ps.setLong(1, System.currentTimeMillis() / 1000);
          ps.setLong(2, existingCertInfo.id);
        }
      }

      ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    }

    LOG.info("Imported  certificate {}", certLogId);
  } // method addCertificate

  private void addCertificateBySerialNumber(AtomicLong maxId, int caId, int crlInfoId,
      BigInteger serialNumber)
          throws DataAccessException {
    LOG.info("Importing certificate by serial number {}", serialNumber);
    CertInfo existingCertInfo = getCertInfo(caId, serialNumber);

    PreparedStatement ps;
    String sql = null;

    try {
      if (existingCertInfo == null) {
        sql = SQL_INSERT_CERT;
        ps = psInsertCert;
        long id = maxId.incrementAndGet();
        int offset = 1;

        ps.setLong(offset++, id);
        // ISSUER ID IID
        ps.setInt(offset++, caId);
        // serial number SN
        ps.setString(offset++, serialNumber.toString(16));
        // whether revoked REV
        ps.setInt(offset++, 0);
        // revocation reason RR
        ps.setNull(offset++, Types.SMALLINT);
        // revocation time RT
        ps.setNull(offset++, Types.BIGINT);
        ps.setNull(offset++, Types.BIGINT);
        // last update LUPDATE
        ps.setLong(offset++, System.currentTimeMillis() / 1000);

        // not before NBEFORE, we use the minimal time
        ps.setLong(offset++, 0);
        // not after NAFTER, use Long.MAX_VALUE
        ps.setLong(offset++, Long.MAX_VALUE);
        ps.setInt(offset++, crlInfoId);
        ps.setString(offset, null);
      } else {
        if (existingCertInfo.revoked | existingCertInfo.crlId != crlInfoId) {
          sql = SQL_UPDATE_CERT;
          ps = psUpdateCert;

          int offset = 1;
          // last update LUPDATE
          ps.setLong(offset++, System.currentTimeMillis() / 1000);

          // not before NBEFORE, we use the minimal time
          ps.setLong(offset++, 0);
          // not after NAFTER, use Long.MAX_VALUE
          ps.setLong(offset++, Long.MAX_VALUE);
          ps.setInt(offset++, crlInfoId);
          ps.setString(offset++, null);
          ps.setLong(offset, existingCertInfo.id);
        } else {
          sql = SQL_UPDATE_CERT_LUPDATE;
          ps = psUpdateCertLastupdate;

          // last update LUPDATE
          ps.setLong(1, System.currentTimeMillis() / 1000);
          ps.setLong(2, existingCertInfo.id);
        }
      }

      ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    }

    LOG.info(" Imported certificate by serial number {}", serialNumber);
  } // method addCertificateBySerialNumber

  private void deleteEntriesNotUpdatedSince(Connection conn, int crlInfoId, long timeSec)
      throws DataAccessException {
    // remove the unmodified entries
    String sql = "DELETE FROM CERT WHERE CRL_ID=" + crlInfoId + " AND LUPDATE<" + timeSec;
    Statement stmt = datasource.createStatement(conn);
    try {
      stmt.executeUpdate(sql);
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      releaseResources(stmt, null);
    }
  } // method deleteEntriesNotUpdatedSince

  private void releaseResources(Statement ps, ResultSet rs) {
    datasource.releaseResources(ps, rs, false);
  }

  private static int getCrlIdFromName(String name) {
    int intvalue = name.hashCode();
    if (intvalue < 0) {
      intvalue *= -1;
    }
    return intvalue;
  }

  private void commit(Connection conn)
      throws DataAccessException {
    try {
      conn.commit();
    } catch (SQLException ex) {
      throw datasource.translate("commit", ex);
    }
  }

  private static String getCrlNameFromDir(File dir) {
    if (!dir.isDirectory()) {
      return null;
    }

    String dirName = dir.getName();
    String crlName = null;

    if (dirName.length() > 4 && dirName.startsWith("crl-")) {
      crlName = dirName.substring(4).trim(); // 4 = "crl-".length()
    }

    return StringUtil.isBlank(dirName) ? null : crlName;
  } // method getCrlNameFromDir

}
