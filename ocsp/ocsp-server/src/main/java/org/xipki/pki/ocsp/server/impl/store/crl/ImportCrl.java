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

package org.xipki.pki.ocsp.server.impl.store.crl;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.ocsp.CrlID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.pki.ocsp.server.impl.store.db.CrlInfo;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgoType;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class ImportCrl {

    private static final Logger LOG = LoggerFactory.getLogger(ImportCrl.class);

    private static final String SQL_UPDATE_CERT_REV
            = "UPDATE CERT SET REV=?,RR=?,RT=?,RIT=?,LUPDATE=? WHERE ID=?";

    private static final String SQL_INSERT_CERT_REV
            = "INSERT INTO CERT (ID,IID,SN,REV,RR,RT,RIT,LUPDATE) VALUES(?,?,?,?,?,?,?,?)";

    private static final String SQL_DELETE_CERT
            = "DELETE FROM CERT WHERE IID=? AND SN=?";

    private static final String SQL_UPDATE_CERT
            = "UPDATE CERT SET LUPDATE=?,NBEFORE=?,NAFTER=?,PN=? WHERE ID=?";

    private static final String SQL_INSERT_CERT
            = "INSERT INTO CERT (ID,IID,SN,REV,RR,RT,RIT,LUPDATE,NBEFORE,NAFTER,PN) "
              + "VALUES(?,?,?,?,?,?,?,?,?,?,?)";

    private static final String SQL_INSERT_CERTHASH
            = "INSERT INTO CHASH (CID,S1,S224,S256,S384,S512) VALUES(?,?,?,?,?,?)";

    private static final String CORE_SQL_SELECT_ID_CERT
            = "ID FROM CERT WHERE IID=? AND SN=?";

    private static final String CORESQL_SELECT_CID_CERTHASH
            = "1 FROM CHASH WHERE CID=?";

    private final String sqlSelectIdCert;

    private final String sqlSelectCidCertHash;

    private final X509CRL crl;

    private final X509Certificate caCert;

    private final BigInteger crlNumber;

    private final DataSourceWrapper datasource;

    private final boolean useCrlUpdates;

    // The CRL number of a DeltaCRL.
    private final BigInteger baseCrlNumber;

    private final boolean isDeltaCrl;

    private final CrlID crlId;

    private final X500Name caSubject;

    private final byte[] caSpki;

    private final String certsDirName;

    private final CertRevocationInfo caRevInfo;

    private PreparedStatement psDeleteCert;
    private PreparedStatement psInsertCert;
    private PreparedStatement psInsertCertRev;
    private PreparedStatement psInsertCertHash;
    private PreparedStatement psSelectCidCertHash;
    private PreparedStatement psSelectIdCert;
    private PreparedStatement psUpdateCert;
    private PreparedStatement psUpdateCertRev;

    public ImportCrl(DataSourceWrapper datasource, boolean useCrlUpdates, X509CRL crl,
            String crlUrl, X509Certificate caCert, X509Certificate issuerCert,
            CertRevocationInfo caRevInfo, String certsDirName) throws ImportCrlException {
        this.datasource = ParamUtil.requireNonNull("datasource", datasource);
        this.useCrlUpdates = useCrlUpdates;
        this.crl = ParamUtil.requireNonNull("crl", crl);
        this.caCert = ParamUtil.requireNonNull("caCert", caCert);
        this.caSubject = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
        try {
            this.caSpki = X509Util.extractSki(caCert);
        } catch (CertificateEncodingException ex) {
            throw new ImportCrlException("could not extract AKI of CA certificate", ex);
        }

        this.certsDirName = certsDirName;
        this.caRevInfo = caRevInfo;

        X500Principal issuer = crl.getIssuerX500Principal();

        boolean caAsCrlIssuer = true;
        if (!caCert.getSubjectX500Principal().equals(issuer)) {
            caAsCrlIssuer = false;
            if (issuerCert == null) {
                throw new IllegalArgumentException("issuerCert must not be null");
            }

            if (!issuerCert.getSubjectX500Principal().equals(issuer)) {
                throw new IllegalArgumentException("issuerCert and CRL do not match");
            }
        }

        // Verify the signature
        X509Certificate crlSignerCert = caAsCrlIssuer ? caCert : issuerCert;
        try {
            crl.verify(crlSignerCert.getPublicKey());
        } catch (SignatureException | NoSuchProviderException | InvalidKeyException | CRLException
                | NoSuchAlgorithmException ex) {
            throw new ImportCrlException("could not verify signature of CRL", ex);
        }

        byte[] octetString = crl.getExtensionValue(Extension.cRLNumber.getId());
        if (octetString == null) {
            throw new IllegalArgumentException("CRL without CRLNumber is not supported");
        }
        ASN1Integer asn1CrlNumber
                = ASN1Integer.getInstance(DEROctetString.getInstance(octetString).getOctets());
        this.crlNumber = asn1CrlNumber.getPositiveValue();

        octetString = crl.getExtensionValue(Extension.deltaCRLIndicator.getId());
        this.isDeltaCrl = (octetString != null);
        if (this.isDeltaCrl) {
            LOG.info("The CRL a DeltaCRL");
            byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
            this.baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
        } else {
            LOG.info("The CRL a full CRL");
            this.baseCrlNumber = null;
        }

        // Construct CrlID
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (StringUtil.isNotBlank(crlUrl)) {
            vec.add(new DERTaggedObject(true, 0, new DERIA5String(crlUrl, true)));
        }

        vec.add(new DERTaggedObject(true, 1, asn1CrlNumber));
        vec.add(new DERTaggedObject(true, 2, new DERGeneralizedTime(crl.getThisUpdate())));
        this.crlId = CrlID.getInstance(new DERSequence(vec));

        this.sqlSelectCidCertHash = datasource.buildSelectFirstSql(1, CORESQL_SELECT_CID_CERTHASH);
        this.sqlSelectIdCert = datasource.buildSelectFirstSql(1, CORE_SQL_SELECT_ID_CERT);
    }

    public boolean importCrlToOcspDb() {
        Connection conn = null;
        try {
            conn = datasource.getConnection();

            // CHECKSTYLE:SKIP
            Date startTime = new Date();
            // CHECKSTYLE:SKIP
            int caId = importCa(conn);

            psDeleteCert = datasource.prepareStatement(conn, SQL_DELETE_CERT);
            psInsertCert = datasource.prepareStatement(conn, SQL_INSERT_CERT);
            psInsertCertRev = datasource.prepareStatement(conn, SQL_INSERT_CERT_REV);
            psInsertCertHash = datasource.prepareStatement(conn, SQL_INSERT_CERTHASH);
            psSelectCidCertHash = datasource.prepareStatement(conn, sqlSelectCidCertHash);
            psSelectIdCert = datasource.prepareStatement(conn, sqlSelectIdCert);
            psUpdateCert = datasource.prepareStatement(conn, SQL_UPDATE_CERT);
            psUpdateCertRev = datasource.prepareStatement(conn, SQL_UPDATE_CERT_REV);

            importEntries(conn, caId);
            deleteEntriesNotUpdatedSince(conn, startTime);

            return true;
        } catch (Throwable th) {
            LogUtil.error(LOG, th, "could not import CRL to OCSP database");
            releaseResources(psDeleteCert, null);
            releaseResources(psInsertCert, null);
            releaseResources(psInsertCertRev, null);
            releaseResources(psInsertCertHash, null);
            releaseResources(psSelectCidCertHash, null);
            releaseResources(psSelectIdCert, null);
            releaseResources(psUpdateCert, null);
            releaseResources(psUpdateCertRev, null);

            if (conn != null) {
                datasource.returnConnection(conn);
            }
        }

        return false;
    }

    private int importCa(Connection conn)
            throws DataAccessException, ImportCrlException {
        byte[] encodedCaCert;
        try {
            encodedCaCert = caCert.getEncoded();
        } catch (CertificateEncodingException ex) {
            throw new ImportCrlException("could not encode CA certificate");
        }
        String fpCaCert = HashAlgoType.SHA1.base64Hash(encodedCaCert);

        Integer issuerId = null;
        CrlInfo crlInfo = null;

        PreparedStatement ps = null;
        ResultSet rs = null;
        String sql = null;
        try {
            sql = "SELECT ID,CRL_INFO FROM ISSUER WHERE S1C=?";
            ps = datasource.prepareStatement(conn, sql);
            ps.setString(1, fpCaCert);
            rs = ps.executeQuery();
            if (rs.next()) {
                issuerId = rs.getInt("ID");
                String str = rs.getString("CRL_INFO");
                if (str == null) {
                    throw new ImportCrlException(
                            "Issuer for the given CA of CRL exists, but not imported from CRL");
                }
                crlInfo = new CrlInfo(str);
            }
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        } finally {
            releaseResources(ps, rs);
        }

        boolean addNew = (issuerId == null);
        if (addNew) {
            if (isDeltaCrl) {
                throw new ImportCrlException("Given CRL is a deltaCRL for the full CRL with number "
                        + baseCrlNumber + ", please import this full CRL first.");
            } else {
                crlInfo = new CrlInfo(crlNumber, null, useCrlUpdates, crl.getThisUpdate(),
                        crl.getNextUpdate(), crlId);
            }
        } else {
            if (crlNumber.compareTo(crlInfo.crlNumber()) < 0) {
                // It is permitted if the CRL number equals to the one in Database,
                // which enables the resume of importing process if error occurred.
                throw new ImportCrlException("Given CRL is not newer than existing CRL.");
            }

            if (isDeltaCrl) {
                BigInteger lastFullCrlNumber = crlInfo.baseCrlNumber();
                if (lastFullCrlNumber == null) {
                    lastFullCrlNumber = crlInfo.crlNumber();
                }

                if (!baseCrlNumber.equals(lastFullCrlNumber)) {
                    throw new ImportCrlException(
                            "Given CRL is a deltaCRL for the full CRL with number "
                            + crlNumber + ", please import this full CRL first.");
                }
            }

            crlInfo.setCrlNumber(crlNumber);
            crlInfo.setBaseCrlNumber(isDeltaCrl ? baseCrlNumber : null);
            crlInfo.setThisUpdate(crl.getThisUpdate());
            crlInfo.setNextUpdate(crl.getNextUpdate());
        }

        ps = null;
        rs = null;
        sql = null;
        try {

            // issuer exists
            if (addNew) {
                int maxId = (int) datasource.getMax(conn, "ISSUER", "ID");
                issuerId = maxId + 1;

                sql = "INSERT INTO ISSUER (ID,SUBJECT,NBEFORE,NAFTER,S1C,CERT,REV,RT,RIT,CRL_INFO)"
                        + " VALUES(?,?,?,?,?,?,?,?,?,?)";
            } else {
                sql = "UPDATE ISSUER SET REV=?,RT=?,RIT=?,CRL_INFO=? WHERE ID=?";
            }

            ps = datasource.prepareStatement(conn, sql);

            int offset = 1;

            if (addNew) {
                String subject = X509Util.getRfc4519Name(caCert.getSubjectX500Principal());
                ps.setInt(offset++, issuerId);
                ps.setString(offset++, subject);
                ps.setLong(offset++, caCert.getNotBefore().getTime() / 1000);
                ps.setLong(offset++, caCert.getNotAfter().getTime() / 1000);
                ps.setString(offset++, fpCaCert);
                ps.setString(offset++, Base64.toBase64String(encodedCaCert));
            }

            ps.setInt(offset++, (caRevInfo == null) ? 0 : 1);
            Date revTime = null;
            Date revInvTime = null;
            if (caRevInfo != null) {
                revTime = caRevInfo.revocationTime();
                revInvTime = caRevInfo.invalidityTime();
            }

            if (revTime != null) {
                ps.setLong(offset++, revTime.getTime() / 1000);
            } else {
                ps.setNull(offset++, Types.BIGINT);
            }

            if (revInvTime != null) {
                ps.setLong(offset++, revInvTime.getTime() / 1000);
            } else {
                ps.setNull(offset++, Types.BIGINT);
            }

            // CRL info
            try {
                ps.setString(offset++, crlInfo.getEncoded());
            } catch (IOException ex) {
                throw new ImportCrlException("could not encode the Crlinfo", ex);
            }

            if (!addNew) {
                ps.setInt(offset++, issuerId.intValue());
            }

            ps.executeUpdate();
            return issuerId.intValue();
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        } finally {
            releaseResources(ps, rs);
        }
    }

    private void importEntries(Connection conn, int caId)
            throws DataAccessException, ImportCrlException {

        AtomicLong maxId = new AtomicLong(datasource.getMax(conn, "CERT", "ID"));

        // import the revoked information
        Set<? extends X509CRLEntry> revokedCertList = crl.getRevokedCertificates();
        if (revokedCertList != null) {
            for (X509CRLEntry c : revokedCertList) {
                X500Principal issuer = c.getCertificateIssuer();
                BigInteger serial = c.getSerialNumber();

                if (issuer != null && !caSubject.equals(issuer)) {
                    throw new ImportCrlException("invalid CRLEntry for certificate number "
                            + serial);
                }

                Date rt = c.getRevocationDate();
                Date rit = null;
                byte[] extnValue = c.getExtensionValue(Extension.invalidityDate.getId());
                if (extnValue != null) {
                    extnValue = extractCoreValue(extnValue);
                    ASN1GeneralizedTime genTime = DERGeneralizedTime.getInstance(extnValue);
                    try {
                        rit = genTime.getDate();
                    } catch (ParseException ex) {
                        throw new ImportCrlException(ex.getMessage(), ex);
                    }

                    if (rt.equals(rit)) {
                        rit = null;
                    }
                }

                CrlReason reason = CrlReason.fromReason(c.getRevocationReason());

                String sql = null;
                try {
                    if (reason == CrlReason.REMOVE_FROM_CRL) {
                        if (!isDeltaCrl) {
                            LOG.warn("ignore CRL entry with reason removeFromCRL in non-Delta CRL");
                        }

                        // delete the entry
                        sql = SQL_DELETE_CERT;
                        psDeleteCert.setInt(1, caId);
                        psDeleteCert.setString(2, serial.toString(16));
                        psDeleteCert.executeUpdate();
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
                    ps.setInt(offset++, reason.code());
                    ps.setLong(offset++, rt.getTime() / 1000);
                    if (rit != null) {
                        ps.setLong(offset++, rit.getTime() / 1000);
                    } else {
                        ps.setNull(offset++, Types.BIGINT);
                    }
                    ps.setLong(offset++, System.currentTimeMillis() / 1000);

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
        byte[] extnValue = crl.getExtensionValue(ObjectIdentifiers.id_xipki_ext_crlCertset.getId());
        if (extnValue != null) {
            extnValue = extractCoreValue(extnValue);
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

                if (cert != null) {
                    if (!caSubject.equals(cert.getIssuer())) {
                        LOG.warn("issuer not match (serial=" + LogUtil.formatCsn(serialNumber)
                                + ") in CRL Extension Xipki-CertSet, ignore it");
                    }

                    if (!serialNumber.equals(cert.getSerialNumber().getValue())) {
                        LOG.warn("serialNumber not match (serial=" + LogUtil.formatCsn(serialNumber)
                                + ") in CRL Extension Xipki-CertSet, ignore it");
                    }
                }

                String certLogId = "(issuer='" + cert.getIssuer().toString()
                        + "', serialNumber=" + cert.getSerialNumber() + ")";
                addCertificate(maxId, caId, cert, profileName, certLogId);
            }
        } else {
            // cert dirs
            File certsDir = new File(certsDirName);

            if (!certsDir.exists()) {
                LOG.warn("the folder " + certsDirName + " does not exist, ignore it");
                return;
            }

            if (!certsDir.isDirectory()) {
                LOG.warn("the path " + certsDirName + " does not point to a folder, ignore it");
                return;
            }

            if (!certsDir.canRead()) {
                LOG.warn("the folder " + certsDirName + " must not be read, ignore it");
                return;
            }

            File[] certFiles = certsDir.listFiles(new FilenameFilter() {
                @Override
                public boolean accept(final File dir, final String name) {
                    return name.endsWith(".der") || name.endsWith(".crt");
                }
            });

            if (certFiles == null || certFiles.length == 0) {
                return;
            }

            for (File certFile : certFiles) {
                Certificate cert;

                try {
                    byte[] encoded = IoUtil.read(certFile);
                    cert = Certificate.getInstance(encoded);
                } catch (IllegalArgumentException | IOException ex) {
                    LOG.warn("could not parse certificate {}, ignore it", certFile.getPath());
                    continue;
                }

                String certLogId = "(file " + certFile.getName() + ")";
                addCertificate(maxId, caId, cert, null, certLogId);
            }
        }

    }

    private static byte[] extractCoreValue(final byte[] encodedExtensionValue) {
        return ASN1OctetString.getInstance(encodedExtensionValue).getOctets();
    }

    private Long getId(int caId, BigInteger serialNumber)
            throws DataAccessException {
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

    private void addCertificate(AtomicLong maxId, int caId, Certificate cert, String profileName,
            final String certLogId)
            throws DataAccessException, ImportCrlException {
        // not issued by the given issuer
        if (!caSubject.equals(cert.getIssuer())) {
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

        if (caSpki != null) {
            byte[] aki = null;
            try {
                aki = X509Util.extractAki(cert);
            } catch (CertificateEncodingException ex) {
                LogUtil.error(LOG, ex,
                        "invalid AuthorityKeyIdentifier of certificate {}" + certLogId
                        + ", ignore it");
                return;
            }

            if (aki == null || !Arrays.equals(caSpki, aki)) {
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
            // profile name PN
            if (StringUtil.isBlank(profileName)) {
                ps.setNull(offset++, Types.VARCHAR);
            } else {
                ps.setString(offset++, profileName);
            }

            if (sql == SQL_UPDATE_CERT) {
                ps.setLong(offset++, id);
            }

            ps.executeUpdate();
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        }

        boolean insertCertHash = true;
        // then add entry to the table CHASH
        if (tblCertIdExists) {
            sql = sqlSelectCidCertHash;
            ps = psSelectCidCertHash;
            ResultSet rs = null;
            try {
                ps.setLong(1, id);
                rs = ps.executeQuery();
                if (rs.next()) {
                    insertCertHash = false;
                }
            } catch (SQLException ex) {
                throw datasource.translate(sql, ex);
            } finally {
                releaseResources(null, rs);
            }
        }

        if (insertCertHash) {
            sql = SQL_INSERT_CERTHASH;
            ps = psInsertCertHash;
            try {
                int offset = 1;
                ps.setLong(offset++, id);
                ps.setString(offset++, HashAlgoType.SHA1.base64Hash(encodedCert));
                ps.setString(offset++, HashAlgoType.SHA224.base64Hash(encodedCert));
                ps.setString(offset++, HashAlgoType.SHA256.base64Hash(encodedCert));
                ps.setString(offset++, HashAlgoType.SHA384.base64Hash(encodedCert));
                ps.setString(offset++, HashAlgoType.SHA512.base64Hash(encodedCert));
                ps.executeUpdate();
            } catch (SQLException ex) {
                throw datasource.translate(sql, ex);
            }
        }

        // it is not required to add entry to table CRAW
        LOG.info("Imported  certificate {}", certLogId);
    }

    private void deleteEntriesNotUpdatedSince(Connection conn, Date time)
            throws DataAccessException {
        // remove the unmodified entries
        String sql = "DELETE FROM CERT WHERE LUPDATE<" + time.getTime() / 1000;
        Statement stmt = datasource.createStatement(conn);
        try {
            stmt.executeUpdate(sql);
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        } finally {
            releaseResources(stmt, null);
        }
    }

    private void releaseResources(final Statement ps, final ResultSet rs) {
        datasource.releaseResources(ps, rs, false);
    }

}
