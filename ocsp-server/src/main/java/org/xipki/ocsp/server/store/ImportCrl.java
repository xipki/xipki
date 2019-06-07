/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.ocsp.CrlID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.asn1.CrlStreamParser;
import org.xipki.security.asn1.CrlStreamParser.RevokedCert;
import org.xipki.security.asn1.CrlStreamParser.RevokedCertsIterator;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.DateUtil;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

/**
 * Import CRLs to database.
 *
 * @author Lijun Liao
 * @since 2.2.0
 */

class ImportCrl {

  private static class CrlDirInfo {

    private final int crlId;

    private final String crlName;

    private final File crlDir;

    private final boolean updateMe;

    private String base64Sha1Fp;

    private CertRevocationInfo revocationinfo;

    private boolean shareCaWithOtherCrl = false;

    CrlDirInfo(int crlId, String crlName, File crlDir, boolean updateMe) {
      this.crlId = crlId;
      this.crlName = crlName;
      this.crlDir = crlDir;
      this.updateMe = updateMe;
    }

  } // class CrlDirInfo

  private static class CertWrapper {

    private final Certificate cert;

    private final X500Name subject;

    private final String base64Sha1Fp;

    private final String base64Encoded;

    private final byte[] subjectKeyIdentifier;

    private Integer databaseId;

    CertWrapper(Certificate cert) {
      this.cert = cert;
      this.subject = cert.getSubject();
      byte[] encoded;
      try {
        encoded = cert.getEncoded();
      } catch (IOException ex) {
        throw new IllegalArgumentException("error encoding certificate");
      }
      this.base64Sha1Fp = HashAlgo.SHA1.base64Hash(encoded);
      this.base64Encoded = Base64.encodeToString(encoded);
      try {
        this.subjectKeyIdentifier = X509Util.extractSki(cert);
      } catch (CertificateEncodingException ex) {
        throw new IllegalArgumentException("error extracting SubjectKeyIdentifier");
      }
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

  private static final String SQL_UPDATE_CERT
      = "UPDATE CERT SET LUPDATE=?,NBEFORE=?,NAFTER=?,CRL_ID=?,HASH=? WHERE ID=?";

  private static final String SQL_INSERT_CERT
      = "INSERT INTO CERT (ID,IID,SN,REV,RR,RT,RIT,LUPDATE,NBEFORE,NAFTER,CRL_ID,HASH) "
        + "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)";

  private static final String CORE_SQL_SELECT_ID_CERT = "ID FROM CERT WHERE IID=? AND SN=?";

  private final String basedir;

  private final String sqlSelectIdCert;

  private final DataSourceWrapper datasource;

  private final HashAlgo certhashAlgo;

  private PreparedStatement psDeleteCert;

  private PreparedStatement psInsertCert;

  private PreparedStatement psInsertCertRev;

  private PreparedStatement psSelectIdCert;

  private PreparedStatement psUpdateCert;

  private PreparedStatement psUpdateCertRev;

  public ImportCrl(DataSourceWrapper datasource, String basedir) throws DataAccessException {
    this.datasource = Args.notNull(datasource, "datasource");
    this.basedir = Args.notNull(basedir, "basedir");
    this.certhashAlgo = DbCertStatusStore.getCertHashAlgo(datasource);

    LOG.info("UPDATE_CERTSTORE");
    this.sqlSelectIdCert = datasource.buildSelectFirstSql(1, CORE_SQL_SELECT_ID_CERT);
  }

  public boolean importCrlToOcspDb() {
    File[] crlDirs = new File(basedir).listFiles();
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
      CrlDirInfo crlDirInfo = new CrlDirInfo(crlId, crlName, crlDir, updateMe);
      crlDirInfo.base64Sha1Fp = base64Sha1Fp;
      crlDirInfo.revocationinfo = caRevInfo;
      crlDirInfos.add(crlDirInfo);
    }

    // pre processing
    for (CrlDirInfo m : crlDirInfos) {
      File crlDir = m.crlDir;
      if (m.revocationinfo != null) {
        // make sure that revoked CA is not specified in two different folders
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
    try {
      conn = datasource.getConnection();

      psDeleteCert = datasource.prepareStatement(conn, SQL_DELETE_CERT);
      psInsertCert = datasource.prepareStatement(conn, SQL_INSERT_CERT);
      psInsertCertRev = datasource.prepareStatement(conn, SQL_INSERT_CERT_REV);
      psSelectIdCert = datasource.prepareStatement(conn, sqlSelectIdCert);
      psUpdateCert = datasource.prepareStatement(conn, SQL_UPDATE_CERT);
      psUpdateCertRev = datasource.prepareStatement(conn, SQL_UPDATE_CERT_REV);

      for (CrlDirInfo crlDirInfo : crlDirInfos) {
        if (crlDirInfo.updateMe) {
          importCrl(conn, crlDirInfo);
        }
      }

      return true;
    } catch (Throwable th) {
      LogUtil.error(LOG, th, "could not import CRL to OCSP database");
    } finally {
      releaseResources(psDeleteCert, null);
      releaseResources(psInsertCert, null);
      releaseResources(psInsertCertRev, null);
      releaseResources(psSelectIdCert, null);
      releaseResources(psUpdateCert, null);
      releaseResources(psUpdateCertRev, null);

      if (conn != null) {
        datasource.returnConnection(conn);
      }
    }

    return false;
  }

  private void importCrl(Connection conn, CrlDirInfo crlDirInfo) {
    Date startTime = new Date();

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
        Certificate cert = X509Util.parseBcCert(caCertFile);
        caCert = new CertWrapper(cert);
      } catch (CertificateException ex) {
        LOG.error("could not parse CA certificate " + caCertFile.getPath(), ex);
        return;
      }

      CrlStreamParser crl = null;
      CrlInfo crlInfo = null;

      if (crlDirInfo.revocationinfo == null) {
        crl = new CrlStreamParser(new File(crlDir, "ca.crl"));
        Date now = new Date();
        if (crl.getNextUpdate() != null && crl.getNextUpdate().before(now)) {
          LOG.error("CRL is expired");
          return;
        } else if (crl.getThisUpdate().after(now)) {
          LOG.error("CRL is not valid yet");
          return;
        }

        X500Name issuer = crl.getIssuer();

        Certificate crlSignerCert;
        if (caCert.subject.equals(issuer)) {
          crlSignerCert = caCert.cert;
        } else {
          Certificate crlIssuerCert = null;
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
          LOG.error("crlNumber is not specified");
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
          if (crlNumber.compareTo(oldCrlInfo.getCrlNumber()) <= 0) {
            // It is permitted if the CRL number equals to the one in Database,
            // which enables the resume of importing process if error occurred.
            LOG.error("Given CRL is not newer than existing CRL.");
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
          LOG.error("signature of CRL is invalid");
          return;
        }

        crlInfo = new CrlInfo(crlNumber, baseCrlNumber,
            crl.getThisUpdate(), crl.getNextUpdate(), crlId);
      }

      importCa(conn, crlDirInfo, caCert);

      if (crl == null) {
        LOG.info("Ignored CRL (name={}) in the folder {}: CA is revoked",
            crlName, crlDir.getPath());
      } else {
        importCrlInfo(conn, id, crlName, crlInfo,
            crlDirInfo.shareCaWithOtherCrl, caCert.base64Sha1Fp);

        importCrlRevokedCertificates(conn, id, caCert, crl);
        if (!crl.isDeltaCrl()) {
          deleteEntriesNotUpdatedSince(conn, id, startTime);
        }
      }

      updateSucc = true;
      LOG.info("Imported CRL (id={}) in the folder {}", id, crlDir.getPath());
    } catch (Throwable th) {
      LOG.error(String.format(
          "Importing CRL (id=%s) in the folder %s FAILED", id, crlDir.getPath()), th);
    } finally {
      File updatemeFile = new File(crlDirInfo.crlDir, "UPDATEME");
      updatemeFile.setLastModified(System.currentTimeMillis());
      updatemeFile.renameTo(new File(updatemeFile.getPath() + (updateSucc ? ".SUCC" : ".FAIL")));
      if (!updateSucc && caCert != null) {
        if (!crlDirInfo.shareCaWithOtherCrl) {
          // try to delete the issuer if there is not certificate associated with it
          datasource.deleteFromTable(conn, "ISSUER", "ID", caCert.databaseId);
        }
      }
    }
  }

  /**
   * Import the CA certificate with revocation information.
   *
   * @param conn The database connection.
   * @param crlDirInfo CRL directory information.
   * @throws DataAccessException
   *         If database exception occurs.
   * @throws DataAccessException
   *         If IO error occurs.
   * @throws ImportCrlException
   *         If other exception occurs.
   */
  private void importCa(Connection conn, CrlDirInfo crlDirInfo, CertWrapper caCert)
      throws DataAccessException, ImportCrlException, IOException {
    CertRevocationInfo revInfo = crlDirInfo.revocationinfo;

    Integer issuerId = datasource.getFirstValue(conn, "ISSUER", "ID",
        "S1C='" + caCert.base64Sha1Fp + "'", Integer.class);

    PreparedStatement ps = null;
    ResultSet rs = null;
    String sql = null;

    try {
      int offset = 1;
      if (issuerId == null) {
        // issuer not exists
        int maxId = (int) datasource.getMax(conn, "ISSUER", "ID");
        issuerId = maxId + 1;

        sql = "INSERT INTO ISSUER (ID,SUBJECT,NBEFORE,NAFTER,S1C,CERT,REV_INFO)"
            + " VALUES(?,?,?,?,?,?,?)";
        ps = datasource.prepareStatement(conn, sql);
        String subject = X509Util.getRfc4519Name(caCert.subject);

        ps.setInt(offset++, issuerId);
        ps.setString(offset++, subject);
        ps.setLong(offset++, caCert.cert.getStartDate().getDate().getTime() / 1000);
        ps.setLong(offset++, caCert.cert.getEndDate().getDate().getTime() / 1000);
        ps.setString(offset++, caCert.base64Sha1Fp);
        ps.setString(offset++, caCert.base64Encoded);
        ps.setString(offset++, revInfo == null ? null : revInfo.getEncoded());
      } else {
        // issuer exists
        sql = "UPDATE ISSUER SET REV_INFO=? WHERE ID=?";
        ps = datasource.prepareStatement(conn, sql);
        ps.setString(offset++, revInfo == null ? null : revInfo.getEncoded());
        ps.setInt(offset++, issuerId.intValue());
      }

      ps.executeUpdate();

      caCert.databaseId = issuerId;
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      releaseResources(ps, rs);
    }
  }

  private void importCrlInfo(Connection conn, int id, String name, CrlInfo crlInfo,
      boolean shareCaWithOtherCrl, String sha1FpOfIssuerCert) throws DataAccessException {
    boolean exists = datasource.columnExists(conn, "CRL_INFO", "ID", id);

    PreparedStatement ps = null;
    ResultSet rs = null;
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
      releaseResources(ps, rs);
    }

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
      releaseResources(ps, rs);
    }
  }

  private void importCrlRevokedCertificates(Connection conn, int crlInfoId, CertWrapper caCert,
      CrlStreamParser crl) throws DataAccessException, ImportCrlException, IOException {
    int caId = caCert.databaseId.intValue();
    AtomicLong maxId = new AtomicLong(datasource.getMax(conn, "CERT", "ID"));

    boolean isDeltaCrl = crl.isDeltaCrl();
    // import the revoked information
    try (RevokedCertsIterator revokedCertList = crl.revokedCertificates()) {
      while (revokedCertList.hasNext()) {
        RevokedCert revCert = revokedCertList.next();
        BigInteger serial = revCert.getSerialNumber();
        Date rt = revCert.getRevocationDate();
        Date rit = revCert.getInvalidityDate();
        CrlReason reason = revCert.getReason();
        X500Name issuer = revCert.getCertificateIssuer();
        if (issuer != null && !issuer.equals(caCert.subject)) {
          throw new ImportCrlException("invalid CRLEntry for certificate number " + serial);
        }

        String sql = null;
        try {
          if (reason == CrlReason.REMOVE_FROM_CRL) {
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

          Long id = getId(caId, serial);
          PreparedStatement ps;
          int offset = 1;

          if (id == null) {
            sql = SQL_INSERT_CERT_REV;
            id = maxId.incrementAndGet();
            ps = psInsertCertRev;
            ps.setLong(offset++, id);
            ps.setInt(offset++, caId);
            ps.setString(offset++, serial.toString(16));
          } else {
            sql = SQL_UPDATE_CERT_REV;
            ps = psUpdateCertRev;
          }

          ps.setInt(offset++, 1);
          ps.setInt(offset++, reason.getCode());
          ps.setLong(offset++, rt.getTime() / 1000);
          if (rit != null) {
            ps.setLong(offset++, rit.getTime() / 1000);
          } else {
            ps.setNull(offset++, Types.BIGINT);
          }
          ps.setLong(offset++, System.currentTimeMillis() / 1000);
          ps.setInt(offset++, crlInfoId);

          if (ps == psUpdateCertRev) {
            ps.setLong(offset++, id);
          }

          ps.executeUpdate();
        } catch (SQLException ex) {
          throw datasource.translate(sql, ex);
        }
      }
    }

    // import the certificates

    // extract the certificate
    // this extension will be generated only be XiPKI CA.
    byte[] extnValue = X509Util.getCoreExtValue(
                          crl.getCrlExtensions(), ObjectIdentifiers.Xipki.id_xipki_ext_crlCertset);
    if (extnValue != null) {
      ASN1Set asn1Set = DERSet.getInstance(extnValue);
      final int n = asn1Set.size();

      for (int i = 0; i < n; i++) {
        ASN1Encodable asn1 = asn1Set.getObjectAt(i);
        ASN1Sequence seq = ASN1Sequence.getInstance(asn1);
        BigInteger serialNumber = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();

        Certificate cert = null;
        String profileName = null;

        final int size = seq.size();
        for (int j = 1; j < size; j++) {
          ASN1TaggedObject taggedObj = DERTaggedObject.getInstance(seq.getObjectAt(j));
          int tagNo = taggedObj.getTagNo();
          switch (tagNo) {
            case 0:
              cert = Certificate.getInstance(taggedObj.getObject());
              break;
            case 1:
              profileName = DERUTF8String.getInstance(taggedObj.getObject()).getString();
              break;
            default:
              break;
          }
        }

        if (cert == null) {
          continue;
        }

        if (!caCert.subject.equals(cert.getIssuer())) {
          LOG.warn("issuer not match (serial={}) in CRL Extension Xipki-CertSet, ignore it",
              LogUtil.formatCsn(serialNumber));
          continue;
        }

        if (!serialNumber.equals(cert.getSerialNumber().getValue())) {
          LOG.warn("serialNumber not match (serial={}) in CRL Extension Xipki-CertSet, ignore it",
              LogUtil.formatCsn(serialNumber));
          continue;
        }

        String certLogId = "(issuer='" + cert.getIssuer()
            + "', serialNumber=" + cert.getSerialNumber() + ")";
        addCertificate(maxId, crlInfoId, caCert, cert, profileName, certLogId);
      }
    } else {
      // cert dirs
      File certsDir = new File(basedir, "certs");

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
      File[] certFiles = certsDir.listFiles(new FilenameFilter() {
        @Override
        public boolean accept(File dir, String name) {
          return name.endsWith(".der") || name.endsWith(".crt") || name.endsWith(".pem");
        }
      });

      if (certFiles != null && certFiles.length > 0) {
        for (File certFile : certFiles) {
          Certificate cert;
          try {
            cert = X509Util.parseBcCert(certFile);
          } catch (IllegalArgumentException | IOException | CertificateException ex) {
            LOG.warn("could not parse certificate {}, ignore it", certFile.getPath());
            continue;
          }

          String certLogId = "(file " + certFile.getName() + ")";
          addCertificate(maxId, crlInfoId, caCert, cert, null, certLogId);
        }
      }

      // import certificate serial numbers
      File[] serialNumbersFiles = certsDir.listFiles(new FilenameFilter() {
        @Override
        public boolean accept(File dir, String name) {
          return name.endsWith(".serials");
        }
      });

      if (serialNumbersFiles != null && serialNumbersFiles.length > 0) {
        for (File serialNumbersFile : serialNumbersFiles) {
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
        }
      }
    }
  }

  private static Certificate parseCert(File certFile) throws ImportCrlException {
    try {
      return X509Util.parseBcCert(certFile);
    } catch (CertificateException | IOException ex) {
      throw new ImportCrlException("could not parse X.509 certificate from file "
          + certFile + ": " + ex.getMessage(), ex);
    }
  }

  private Long getId(int caId, BigInteger serialNumber) throws DataAccessException {
    ResultSet rs = null;
    try {
      psSelectIdCert.setInt(1, caId);
      psSelectIdCert.setString(2, serialNumber.toString(16));
      rs = psSelectIdCert.executeQuery();
      if (!rs.next()) {
        return null;
      }
      return rs.getLong("ID");
    } catch (SQLException ex) {
      throw datasource.translate(sqlSelectIdCert, ex);
    } finally {
      releaseResources(null, rs);
    }
  }

  private void addCertificate(AtomicLong maxId, int crlInfoId, CertWrapper caCert, Certificate cert,
      String profileName, String certLogId) throws DataAccessException, ImportCrlException {
    // CHECKSTYLE:SKIP
    int caId = caCert.databaseId.intValue();

    // not issued by the given issuer
    if (!caCert.subject.equals(cert.getIssuer())) {
      LOG.warn("certificate {} is not issued by the given CA, ignore it", certLogId);
      return;
    }

    // we don't use the binary read from file, since it may contains redundant ending bytes.
    byte[] encodedCert;
    try {
      encodedCert = cert.getEncoded();
    } catch (IOException ex) {
      throw new ImportCrlException("could not encode certificate {}" + certLogId, ex);
    }
    String b64CertHash = certhashAlgo.base64Hash(encodedCert);

    if (caCert.subjectKeyIdentifier != null) {
      byte[] aki = null;
      try {
        aki = X509Util.extractAki(cert);
      } catch (CertificateEncodingException ex) {
        LogUtil.error(LOG, ex,
            "invalid AuthorityKeyIdentifier of certificate {}" + certLogId + ", ignore it");
        return;
      }

      if (aki == null || !Arrays.equals(caCert.subjectKeyIdentifier, aki)) {
        LOG.warn("certificate {} is not issued by the given CA, ignore it", certLogId);
        return;
      }
    } // end if

    LOG.info("Importing certificate {}", certLogId);
    Long id = getId(caId, cert.getSerialNumber().getPositiveValue());
    boolean tblCertIdExists = (id != null);

    PreparedStatement ps;
    String sql;
    // first update the table CERT
    if (tblCertIdExists) {
      sql = SQL_UPDATE_CERT;
      ps = psUpdateCert;
    } else {
      sql = SQL_INSERT_CERT;
      ps = psInsertCert;
      id = maxId.incrementAndGet();
    }

    try {
      int offset = 1;
      if (sql == SQL_INSERT_CERT) {
        ps.setLong(offset++, id);
        // ISSUER ID IID
        ps.setInt(offset++, caId);
        // serial number SN
        ps.setString(offset++, cert.getSerialNumber().getPositiveValue().toString(16));
        // whether revoked REV
        ps.setInt(offset++, 0);
        // revocation reason RR
        ps.setNull(offset++, Types.SMALLINT);
        // revocation time RT
        ps.setNull(offset++, Types.BIGINT);
        ps.setNull(offset++, Types.BIGINT);
      }

      // last update LUPDATE
      ps.setLong(offset++, System.currentTimeMillis() / 1000);

      TBSCertificate tbsCert = cert.getTBSCertificate();
      // not before NBEFORE
      ps.setLong(offset++, tbsCert.getStartDate().getDate().getTime() / 1000);
      // not after NAFTER
      ps.setLong(offset++, tbsCert.getEndDate().getDate().getTime() / 1000);
      ps.setInt(offset++, crlInfoId);

      ps.setString(offset++, b64CertHash);

      if (sql == SQL_UPDATE_CERT) {
        ps.setLong(offset++, id);
      }

      ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    }

    LOG.info("Imported  certificate {}", certLogId);
  }

  private void addCertificateBySerialNumber(AtomicLong maxId, int caId, int crlInfoId,
      BigInteger serialNumber) throws DataAccessException {
    LOG.info("Importing certificate by serial number {}", serialNumber);
    Long id = getId(caId, serialNumber);
    boolean tblCertIdExists = (id != null);

    PreparedStatement ps;
    String sql;
    // first update the table CERT
    if (tblCertIdExists) {
      sql = SQL_UPDATE_CERT;
      ps = psUpdateCert;
    } else {
      sql = SQL_INSERT_CERT;
      ps = psInsertCert;
      id = maxId.incrementAndGet();
    }

    try {
      int offset = 1;
      if (sql == SQL_INSERT_CERT) {
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
      }

      // last update LUPDATE
      ps.setLong(offset++, System.currentTimeMillis() / 1000);

      // not before NBEFORE, we use the minimal time
      ps.setLong(offset++, 0);
      // not after NAFTER, use Long.MAX_VALUE
      ps.setLong(offset++, Long.MAX_VALUE);
      ps.setInt(offset++, crlInfoId);
      ps.setString(offset++, null);

      if (sql == SQL_UPDATE_CERT) {
        ps.setLong(offset++, id);
      }

      ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    }

    LOG.info(" Imported certificate by serial number {}", serialNumber);
  }

  private void deleteEntriesNotUpdatedSince(Connection conn, int crlInfoId, Date time)
      throws DataAccessException {
    // remove the unmodified entries
    String sql = "DELETE FROM CERT WHERE CRL_ID=" + crlInfoId
                    + " AND LUPDATE<" + time.getTime() / 1000;
    Statement stmt = datasource.createStatement(conn);
    try {
      stmt.executeUpdate(sql);
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      releaseResources(stmt, null);
    }
  }

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
  }

}
