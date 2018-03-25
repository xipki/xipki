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

package org.xipki.ca.server.impl;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.impl.cmp.RequestorEntryWrapper;
import org.xipki.ca.server.impl.cmp.ResponderEntryWrapper;
import org.xipki.ca.server.impl.scep.ScepImpl;
import org.xipki.ca.server.impl.store.CertificateStore;
import org.xipki.ca.server.impl.util.PasswordHash;
import org.xipki.ca.server.mgmt.api.AddUserEntry;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.CaHasUserEntry;
import org.xipki.ca.server.mgmt.api.CaManager;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.ca.server.mgmt.api.CertArt;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.ca.server.mgmt.api.ChangeCaEntry;
import org.xipki.ca.server.mgmt.api.ChangeUserEntry;
import org.xipki.ca.server.mgmt.api.CmpControl;
import org.xipki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.ca.server.mgmt.api.RequestorEntry;
import org.xipki.ca.server.mgmt.api.ResponderEntry;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.api.UserEntry;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.api.x509.CrlControl;
import org.xipki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CaUris;
import org.xipki.ca.server.mgmt.api.x509.X509ChangeCaEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CrlSignerEntry;
import org.xipki.common.ConfPairs;
import org.xipki.common.InvalidConfException;
import org.xipki.common.ObjectCreationException;
import org.xipki.common.util.Base64;
import org.xipki.common.util.DateUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
class CaManagerQueryExecutor {

  private static final Logger LOG = LoggerFactory.getLogger(CaManagerQueryExecutor.class);

  private final DataSourceWrapper datasource;

  private final SQLs sqls;

  CaManagerQueryExecutor(DataSourceWrapper datasource) {
    this.datasource = ParamUtil.requireNonNull("datasource", datasource);
    this.sqls = new SQLs(datasource);
  }

  private X509Certificate generateCert(String b64Cert) throws CaMgmtException {
    if (b64Cert == null) {
      return null;
    }

    byte[] encodedCert = Base64.decode(b64Cert);
    try {
      return X509Util.parseCert(encodedCert);
    } catch (CertificateException ex) {
      throw new CaMgmtException(ex);
    }
  } // method generateCert

  private Statement createStatement() throws CaMgmtException {
    Connection dsConnection;
    try {
      dsConnection = datasource.getConnection();
    } catch (DataAccessException ex) {
      throw new CaMgmtException("could not get connection", ex);
    }

    try {
      return datasource.createStatement(dsConnection);
    } catch (DataAccessException ex) {
      throw new CaMgmtException("could not create statement", ex);
    }
  } // method createStatement

  private PreparedStatement prepareStatement(String sql) throws CaMgmtException {
    Connection dsConnection;
    try {
      dsConnection = datasource.getConnection();
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }

    try {
      return datasource.prepareStatement(dsConnection, sql);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }
  } // method prepareStatement

  /**
   * Retrieve the system event.
   * @param eventName Event name
   * @return the System event, may be {@code null}.
   * @throws CaMgmtException
   *            If error occurs.
   */
  SystemEvent getSystemEvent(String eventName) throws CaMgmtException {
    final String sql = sqls.sqlSelectSystemEvent;
    PreparedStatement ps = null;
    ResultSet rs = null;

    try {
      ps = prepareStatement(sql);
      ps.setString(1, eventName);
      rs = ps.executeQuery();

      if (!rs.next()) {
        return null;
      }

      long eventTime = rs.getLong("EVENT_TIME");
      String eventOwner = rs.getString("EVENT_OWNER");
      return new SystemEvent(eventName, eventOwner, eventTime);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method getSystemEvent

  void deleteSystemEvent(String eventName) throws CaMgmtException {
    final String sql = "DELETE FROM SYSTEM_EVENT WHERE NAME=?";
    PreparedStatement ps = null;

    try {
      ps = prepareStatement(sql);
      ps.setString(1, eventName);
      ps.executeUpdate();
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method deleteSystemEvent

  void addSystemEvent(SystemEvent systemEvent) throws CaMgmtException {
    final String sql =
        "INSERT INTO SYSTEM_EVENT (NAME,EVENT_TIME,EVENT_TIME2,EVENT_OWNER) VALUES (?,?,?,?)";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setString(idx++, systemEvent.getName());
      ps.setLong(idx++, systemEvent.getEventTime());
      ps.setTimestamp(idx++, new Timestamp(systemEvent.getEventTime() * 1000L));
      ps.setString(idx++, systemEvent.getOwner());

      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add system event " + systemEvent.getName());
      }

      LOG.info("added system event {}", systemEvent.getName());
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addSystemEvent

  void changeSystemEvent(SystemEvent systemEvent) throws CaMgmtException {
    deleteSystemEvent(systemEvent.getName());
    addSystemEvent(systemEvent);
  }

  Map<String, String> createEnvParameters() throws CaMgmtException {
    Map<String, String> map = new HashMap<>();
    final String sql = "SELECT NAME,VALUE2 FROM ENVIRONMENT";
    Statement stmt = null;
    ResultSet rs = null;

    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");
        String value = rs.getString("VALUE2");
        map.put(name, value);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }

    return map;
  } // method createEnvParameters

  Map<String, Integer> createCaAliases() throws CaMgmtException {
    Map<String, Integer> map = new HashMap<>();

    final String sql = "SELECT NAME,CA_ID FROM CAALIAS";
    Statement stmt = null;
    ResultSet rs = null;

    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");
        int caId = rs.getInt("CA_ID");
        map.put(name, caId);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }

    return map;
  } // method createCaAliases

  CertprofileEntry createCertprofile(String name) throws CaMgmtException {
    PreparedStatement stmt = null;
    ResultSet rs = null;
    final String sql = sqls.sqlSelectProfile;
    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, name);
      rs = stmt.executeQuery();

      if (!rs.next()) {
        throw new CaMgmtException("unknown CA " + name);
      }

      int id = rs.getInt("ID");
      String type = rs.getString("TYPE");
      String conf = rs.getString("CONF");
      return new CertprofileEntry(new NameId(id, name), type, conf);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createCertprofile

  List<String> namesFromTable(String table) throws CaMgmtException {
    return namesFromTable(table, "NAME");
  }

  List<String> namesFromTable(String table, String nameColumn) throws CaMgmtException {
    final String sql = concat("SELECT ", nameColumn, " FROM ", table);
    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      List<String> names = new LinkedList<>();
      while (rs.next()) {
        String name = rs.getString(nameColumn);
        if (StringUtil.isNotBlank(name)) {
          names.add(name);
        }
      }

      return names;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method getNamesFromTable

  PublisherEntry createPublisher(String name) throws CaMgmtException {
    final String sql = sqls.sqlSelectPublisher;
    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, name);
      rs = stmt.executeQuery();

      if (!rs.next()) {
        throw new CaMgmtException("unkown Publisher " + name);
      }

      int id = rs.getInt("ID");
      String type = rs.getString("TYPE");
      String conf = rs.getString("CONF");
      return new PublisherEntry(new NameId(id, name), type, conf);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createPublisher

  Integer getRequestorId(String requestorName) throws CaMgmtException {
    final String sql = sqls.sqlSelectRequestorId;
    PreparedStatement stmt = null;
    ResultSet rs = null;

    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, requestorName);
      rs = stmt.executeQuery();

      if (!rs.next()) {
        return null;
      }

      return rs.getInt("ID");
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  }

  RequestorEntry createRequestor(String name) throws CaMgmtException {
    final String sql = sqls.sqlSelectRequestor;
    PreparedStatement stmt = null;
    ResultSet rs = null;

    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, name);
      rs = stmt.executeQuery();

      if (!rs.next()) {
        throw new CaMgmtException("unknown Requestor " + name);
      }

      int id = rs.getInt("ID");
      String b64Cert = rs.getString("CERT");
      return new RequestorEntry(new NameId(id, name), b64Cert);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createRequestor

  X509CrlSignerEntry createCrlSigner(String name) throws CaMgmtException {
    final String sql = sqls.sqlSelectCrlSigner;
    PreparedStatement stmt = null;
    ResultSet rs = null;

    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, name);
      rs = stmt.executeQuery();

      if (!rs.next()) {
        throw new CaMgmtException("unknown CRL signer " + name);
      }

      String signerType = rs.getString("SIGNER_TYPE");
      String signerConf = rs.getString("SIGNER_CONF");
      String signerCert = rs.getString("SIGNER_CERT");
      String crlControlConf = rs.getString("CRL_CONTROL");
      return new X509CrlSignerEntry(name, signerType, signerConf, signerCert, crlControlConf);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } catch (InvalidConfException ex) {
      throw new CaMgmtException(ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createCrlSigner

  CmpControlEntry createCmpControl(String name) throws CaMgmtException {
    final String sql = sqls.sqlSelectCmpControl;
    PreparedStatement stmt = null;
    ResultSet rs = null;

    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, name);
      rs = stmt.executeQuery();

      if (!rs.next()) {
        throw new CaMgmtException("unknown CMP control " + name);
      }

      String conf = rs.getString("CONF");
      return new CmpControlEntry(name, conf);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createCmpControl

  ResponderEntry createResponder(String name) throws CaMgmtException {
    final String sql = sqls.sqlSelectResponder;
    PreparedStatement stmt = null;
    ResultSet rs = null;

    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, name);
      rs = stmt.executeQuery();

      if (!rs.next()) {
        throw new CaMgmtException("unknown responder " + name);
      }

      String type = rs.getString("TYPE");
      String conf = rs.getString("CONF");
      String b64Cert = rs.getString("CERT");
      return new ResponderEntry(name, type, conf, b64Cert);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createResponder

  X509CaInfo createCaInfo(String name, boolean masterMode, CertificateStore certstore)
      throws CaMgmtException {
    final String sql = sqls.sqlSelectCa;
    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, name);
      rs = stmt.executeQuery();

      if (!rs.next()) {
        throw new CaMgmtException("uknown CA " + name);
      }

      int artCode = rs.getInt("ART");
      if (artCode != CertArt.X509PKC.getCode()) {
        throw new CaMgmtException("CA " + name + " is not X509CA, and is not supported");
      }

      String crlUris = rs.getString("CRL_URIS");
      String deltaCrlUris = rs.getString("DELTACRL_URIS");

      CertRevocationInfo revocationInfo = null;
      boolean revoked = rs.getBoolean("REV");
      if (revoked) {
        int revReason = rs.getInt("RR");
        long revTime = rs.getInt("RT");
        long revInvalidityTime = rs.getInt("RIT");
        Date revInvTime = (revInvalidityTime == 0) ? null : new Date(revInvalidityTime * 1000);
        revocationInfo = new CertRevocationInfo(revReason, new Date(revTime * 1000), revInvTime);
      }

      List<String> tmpCrlUris = null;
      if (StringUtil.isNotBlank(crlUris)) {
        tmpCrlUris = StringUtil.splitByComma(crlUris);
      }

      List<String> tmpDeltaCrlUris = null;
      if (StringUtil.isNotBlank(deltaCrlUris)) {
        tmpDeltaCrlUris = StringUtil.splitByComma(deltaCrlUris);
      }

      String ocspUris = rs.getString("OCSP_URIS");
      List<String> tmpOcspUris = null;
      if (StringUtil.isNotBlank(ocspUris)) {
        tmpOcspUris = StringUtil.splitByComma(ocspUris);
      }

      String caCertUris = rs.getString("CACERT_URIS");
      List<String> tmpCaCertUris = null;
      if (StringUtil.isNotBlank(caCertUris)) {
        tmpCaCertUris = StringUtil.splitByComma(caCertUris);
      }

      X509CaUris caUris = new X509CaUris(tmpCaCertUris, tmpOcspUris, tmpCrlUris, tmpDeltaCrlUris);

      int id = rs.getInt("ID");
      int serialNoSize = rs.getInt("SN_SIZE");
      long nextCrlNo = rs.getLong("NEXT_CRLNO");
      String signerType = rs.getString("SIGNER_TYPE");
      String signerConf = rs.getString("SIGNER_CONF");
      int numCrls = rs.getInt("NUM_CRLS");
      int expirationPeriod = rs.getInt("EXPIRATION_PERIOD");

      X509CaEntry entry = new X509CaEntry(new NameId(id, name), serialNoSize,
          nextCrlNo, signerType, signerConf, caUris, numCrls, expirationPeriod);
      String b64cert = rs.getString("CERT");
      X509Certificate cert = generateCert(b64cert);
      entry.setCert(cert);

      String status = rs.getString("STATUS");
      CaStatus caStatus = CaStatus.forName(status);
      entry.setStatus(caStatus);

      String maxValidityS = rs.getString("MAX_VALIDITY");
      CertValidity maxValidity = CertValidity.getInstance(maxValidityS);
      entry.setMaxValidity(maxValidity);

      int keepExpiredCertDays = rs.getInt("KEEP_EXPIRED_CERT_DAYS");
      entry.setKeepExpiredCertInDays(keepExpiredCertDays);

      String crlsignerName = rs.getString("CRLSIGNER_NAME");
      if (StringUtil.isNotBlank(crlsignerName)) {
        entry.setCrlSignerName(crlsignerName);
      }

      String responderName = rs.getString("RESPONDER_NAME");
      if (StringUtil.isNotBlank(responderName)) {
        entry.setResponderName(responderName);
      }

      String extraControl = rs.getString("EXTRA_CONTROL");
      if (StringUtil.isNotBlank(extraControl)) {
        entry.setExtraControl(new ConfPairs(extraControl).unmodifiable());
      }

      String cmpcontrolName = rs.getString("CMPCONTROL_NAME");
      if (StringUtil.isNotBlank(cmpcontrolName)) {
        entry.setCmpControlName(cmpcontrolName);
      }

      boolean duplicateKeyPermitted = (rs.getInt("DUPLICATE_KEY") != 0);
      entry.setDuplicateKeyPermitted(duplicateKeyPermitted);

      boolean duplicateSubjectPermitted = (rs.getInt("DUPLICATE_SUBJECT") != 0);
      entry.setDuplicateSubjectPermitted(duplicateSubjectPermitted);

      boolean saveReq = (rs.getInt("SAVE_REQ") != 0);
      entry.setSaveRequest(saveReq);

      int permission = rs.getInt("PERMISSION");
      entry.setPermission(permission);
      entry.setRevocationInfo(revocationInfo);

      String validityModeS = rs.getString("VALIDITY_MODE");
      ValidityMode validityMode = null;
      if (validityModeS != null) {
        validityMode = ValidityMode.forName(validityModeS);
      }
      if (validityMode == null) {
        validityMode = ValidityMode.STRICT;
      }
      entry.setValidityMode(validityMode);

      try {
        return new X509CaInfo(entry, certstore);
      } catch (OperationException ex) {
        throw new CaMgmtException(ex);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createCaInfo

  Set<CaHasRequestorEntry> createCaHasRequestors(NameId ca) throws CaMgmtException {
    Map<Integer, String> idNameMap = getIdNameMap("REQUESTOR");

    final String sql =
        "SELECT REQUESTOR_ID,RA,PERMISSION,PROFILES FROM CA_HAS_REQUESTOR WHERE CA_ID=?";
    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      stmt.setInt(1, ca.getId());
      rs = stmt.executeQuery();

      Set<CaHasRequestorEntry> ret = new HashSet<>();
      while (rs.next()) {
        int id = rs.getInt("REQUESTOR_ID");
        String name = idNameMap.get(id);

        boolean ra = rs.getBoolean("RA");
        int permission = rs.getInt("PERMISSION");
        String str = rs.getString("PROFILES");
        List<String> list = StringUtil.splitByComma(str);
        Set<String> profiles = (list == null) ? null : new HashSet<>(list);
        CaHasRequestorEntry entry = new CaHasRequestorEntry(new NameId(id, name));
        entry.setRa(ra);
        entry.setPermission(permission);
        entry.setProfiles(profiles);

        ret.add(entry);
      }

      return ret;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createCaHasRequestors

  Set<Integer> createCaHasProfiles(NameId ca) throws CaMgmtException {
    final String sql = "SELECT PROFILE_ID FROM CA_HAS_PROFILE WHERE CA_ID=?";
    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      stmt.setInt(1, ca.getId());
      rs = stmt.executeQuery();

      Set<Integer> ret = new HashSet<>();
      while (rs.next()) {
        int id = rs.getInt("PROFILE_ID");
        ret.add(id);
      }

      return ret;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createCaHasProfiles

  Set<Integer> createCaHasPublishers(NameId ca) throws CaMgmtException {
    final String sql = "SELECT PUBLISHER_ID FROM CA_HAS_PUBLISHER WHERE CA_ID=?";
    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      stmt.setInt(1, ca.getId());
      rs = stmt.executeQuery();

      Set<Integer> ret = new HashSet<>();
      while (rs.next()) {
        int id = rs.getInt("PUBLISHER_ID");
        ret.add(id);
      }

      return ret;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createCaHasNames

  boolean deleteRowWithName(String name, String table) throws CaMgmtException {
    return deleteRowWithName(name, table, false);
  }

  private boolean deleteRowWithName(String name, String table, boolean force)
      throws CaMgmtException {
    if (!force) {
      if ("ENVIRONMENT".equalsIgnoreCase(table)) {
        if (CaManagerImpl.ENV_EPOCH.equalsIgnoreCase(name)) {
          throw new CaMgmtException("environment " + name + " is reserved");
        }
      }
    }

    final String sql = concat("DELETE FROM ", table, " WHERE NAME=?");
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, name);
      return ps.executeUpdate() > 0;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method deleteRowWithName

  boolean deleteRows(String table) throws CaMgmtException {
    final String sql = "DELETE FROM " + table;
    Statement stmt = null;
    try {
      stmt = createStatement();
      return stmt.executeUpdate(sql) > 0;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, null);
    }
  } // method deleteRows

  void addCa(CaEntry caEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("caEntry", caEntry);
    if (!(caEntry instanceof X509CaEntry)) {
      throw new CaMgmtException("unsupported CAEntry " + caEntry.getClass().getName());
    }

    try {
      int id = (int) datasource.getMax(null, "CA", "ID");
      caEntry.getIdent().setId(id + 1);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }

    X509CaEntry entry = (X509CaEntry) caEntry;

    final String sql = "INSERT INTO CA (ID,NAME,ART,SUBJECT,SN_SIZE,NEXT_CRLNO,STATUS,CRL_URIS,"
        + "DELTACRL_URIS,OCSP_URIS,CACERT_URIS,MAX_VALIDITY,CERT,SIGNER_TYPE,CRLSIGNER_NAME,"
        + "RESPONDER_NAME,CMPCONTROL_NAME,DUPLICATE_KEY,DUPLICATE_SUBJECT,SAVE_REQ,PERMISSION,"
        + "NUM_CRLS,EXPIRATION_PERIOD,KEEP_EXPIRED_CERT_DAYS,VALIDITY_MODE,EXTRA_CONTROL,"
        + "SIGNER_CONF) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    // insert to table ca
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setInt(idx++, entry.getIdent().getId());
      ps.setString(idx++, entry.getIdent().getName());
      ps.setInt(idx++, CertArt.X509PKC.getCode());
      ps.setString(idx++, entry.getSubject());
      ps.setInt(idx++, entry.getSerialNoBitLen());
      ps.setLong(idx++, entry.getNextCrlNumber());
      ps.setString(idx++, entry.getStatus().getStatus());
      ps.setString(idx++, entry.getCrlUrisAsString());
      ps.setString(idx++, entry.getDeltaCrlUrisAsString());
      ps.setString(idx++, entry.getOcspUrisAsString());
      ps.setString(idx++, entry.getCaCertUrisAsString());
      ps.setString(idx++, entry.getMaxValidity().toString());
      byte[] encodedCert = entry.getCert().getEncoded();
      ps.setString(idx++, Base64.encodeToString(encodedCert));
      ps.setString(idx++, entry.getSignerType());
      ps.setString(idx++, entry.getCrlSignerName());
      ps.setString(idx++, entry.getResponderName());
      ps.setString(idx++, entry.getCmpControlName());
      setBoolean(ps, idx++, entry.isDuplicateKeyPermitted());
      setBoolean(ps, idx++, entry.isDuplicateSubjectPermitted());
      setBoolean(ps, idx++, entry.isSaveRequest());
      ps.setInt(idx++, entry.getPermission());
      ps.setInt(idx++, entry.getNumCrls());
      ps.setInt(idx++, entry.getExpirationPeriod());
      ps.setInt(idx++, entry.getKeepExpiredCertInDays());
      ps.setString(idx++, entry.getValidityMode().name());
      ConfPairs extraControl = entry.getExtraControl();
      String encodedExtraCtrl = (extraControl == null) ? null : extraControl.getEncoded();
      if (StringUtil.isBlank(encodedExtraCtrl)) {
        ps.setString(idx++, null);
      } else {
        ps.setString(idx++, encodedExtraCtrl);
      }
      ps.setString(idx++, entry.getSignerConf());
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add CA " + entry.getIdent());
      }
      if (LOG.isInfoEnabled()) {
        LOG.info("add CA '{}': {}", entry.getIdent(), entry.toString(false, true));
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } catch (CertificateEncodingException ex) {
      throw new CaMgmtException(ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addCa

  void addCaAlias(String aliasName, NameId ca) throws CaMgmtException {
    ParamUtil.requireNonNull("aliasName", aliasName);
    ParamUtil.requireNonNull("ca", ca);

    final String sql = "INSERT INTO CAALIAS (NAME,CA_ID) VALUES (?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, aliasName);
      ps.setInt(2, ca.getId());
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add CA alias " + aliasName);
      }
      LOG.info("added CA alias '{}' for CA '{}'", aliasName, ca);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addCaAlias

  void addCertprofile(CertprofileEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    final String sql = "INSERT INTO PROFILE (ID,NAME,ART,TYPE,CONF) VALUES (?,?,?,?,?)";

    try {
      int id = (int) datasource.getMax(null, "PROFILE", "ID");
      dbEntry.getIdent().setId(id + 1);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setInt(idx++, dbEntry.getIdent().getId());
      ps.setString(idx++, dbEntry.getIdent().getName());
      ps.setInt(idx++, CertArt.X509PKC.getCode());
      ps.setString(idx++, dbEntry.getType());
      String conf = dbEntry.getConf();
      ps.setString(idx++, conf);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add CertProfile " + dbEntry.getIdent());
      }

      LOG.info("added profile '{}': {}", dbEntry.getIdent(), dbEntry);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addCertprofile

  void addCertprofileToCa(NameId profile, NameId ca) throws CaMgmtException {
    ParamUtil.requireNonNull("profile", profile);
    ParamUtil.requireNonNull("ca", ca);

    final String sql = "INSERT INTO CA_HAS_PROFILE (CA_ID,PROFILE_ID) VALUES (?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setInt(1, ca.getId());
      ps.setInt(2, profile.getId());
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add profile " + profile + " to CA " + ca);
      }

      LOG.info("added profile '{}' to CA '{}'", profile, ca);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addCertprofileToCa

  void addCmpControl(CmpControlEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    final String name = dbEntry.getName();
    final String sql = "INSERT INTO CMPCONTROL (NAME,CONF) VALUES (?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setString(idx++, name);
      ps.setString(idx++, dbEntry.getConf());
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add CMP control " + name);
      }

      LOG.info("added CMP control: {}", dbEntry);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addCmpControl

  void addRequestor(RequestorEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);

    try {
      int id = (int) datasource.getMax(null, "REQUESTOR", "ID");
      dbEntry.getIdent().setId(id + 1);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }

    final String sql = "INSERT INTO REQUESTOR (ID,NAME,CERT) VALUES (?,?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setInt(idx++, dbEntry.getIdent().getId());
      ps.setString(idx++, dbEntry.getIdent().getName());
      ps.setString(idx++, Base64.encodeToString(dbEntry.getCert().getEncoded()));
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add requestor " + dbEntry.getIdent());
      }

      if (LOG.isInfoEnabled()) {
        LOG.info("added requestor '{}': {}", dbEntry.getIdent(), dbEntry.toString(false));
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } catch (CertificateEncodingException ex) {
      throw new CaMgmtException(ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addRequestor

  void addRequestorIfNeeded(String requestorName) throws CaMgmtException {
    String sql = sqls.sqlSelectRequestorId;
    ResultSet rs = null;
    PreparedStatement stmt = null;
    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, requestorName);
      rs = stmt.executeQuery();
      if (rs.next()) {
        return;
      }
      datasource.releaseResources(stmt, rs);
      stmt = null;
      rs = null;

      int id = (int) datasource.getMax(null, "REQUESTOR", "ID");

      sql = "INSERT INTO REQUESTOR (ID,NAME) VALUES (?,?)";
      stmt = prepareStatement(sql);
      stmt.setInt(1, id + 1);
      stmt.setString(2, requestorName);
      stmt.executeUpdate();
      LOG.info("added requestor '{}'", requestorName);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  }

  void addRequestorToCa(CaHasRequestorEntry requestor, NameId ca) throws CaMgmtException {
    ParamUtil.requireNonNull("requestor", requestor);
    ParamUtil.requireNonNull("ca", ca);

    final NameId requestorIdent = requestor.getRequestorIdent();

    PreparedStatement ps = null;
    final String sql = "INSERT INTO CA_HAS_REQUESTOR (CA_ID,REQUESTOR_ID,RA, PERMISSION,PROFILES)"
        + " VALUES (?,?,?,?,?)";
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setInt(idx++, ca.getId());
      ps.setInt(idx++, requestorIdent.getId());

      boolean ra = requestor.isRa();
      setBoolean(ps, idx++, ra);
      int permission = requestor.getPermission();
      ps.setInt(idx++, permission);
      String profilesText = StringUtil.collectionAsStringByComma(requestor.getProfiles());
      ps.setString(idx++, profilesText);

      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add requestor " + requestorIdent + " to CA " + ca);
      }

      LOG.info("added requestor '{}' to CA '{}': ra: {}; permission: {}; profile: {}",
          requestorIdent, ca, ra, permission, profilesText);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addRequestorToCa

  void addCrlSigner(X509CrlSignerEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    String crlControl = dbEntry.crlControl();
    // validate crlControl
    if (crlControl != null) {
      try {
        new CrlControl(crlControl);
      } catch (InvalidConfException ex) {
        throw new CaMgmtException(concat("invalid CRL control '", crlControl, "'"));
      }
    }

    String name = dbEntry.getName();
    String sql = "INSERT INTO CRLSIGNER (NAME,SIGNER_TYPE,SIGNER_CERT,CRL_CONTROL,SIGNER_CONF)"
        + " VALUES (?,?,?,?,?)";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setString(idx++, name);
      ps.setString(idx++, dbEntry.getType());
      ps.setString(idx++, (dbEntry.getCert() == null) ? null
            : Base64.encodeToString(dbEntry.getCert().getEncoded()));
      ps.setString(idx++, crlControl);
      ps.setString(idx++, dbEntry.getConf());

      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add CRL signer " + name);
      }

      LOG.info("added CRL signer '{}': {}", name, dbEntry.toString(false, true));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } catch (CertificateEncodingException ex) {
      throw new CaMgmtException(ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addCrlSigner

  String setEpoch(Date time) throws CaMgmtException {
    deleteRowWithName(CaManagerImpl.ENV_EPOCH, "ENVIRONMENT", true);
    String envEpoch = DateUtil.toUtcTimeyyyyMMdd(time);
    addEnvParam(CaManagerImpl.ENV_EPOCH, envEpoch, true);
    return envEpoch;
  }

  void addEnvParam(String name, String value) throws CaMgmtException {
    addEnvParam(name, value, false);
  }

  private void addEnvParam(String name, String value, boolean force) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonNull("value", value);
    if (!force) {
      if (CaManagerImpl.ENV_EPOCH.equalsIgnoreCase(name)) {
        throw new CaMgmtException("environment " + name + " is reserved");
      }
    }
    final String sql = "INSERT INTO ENVIRONMENT (NAME,VALUE2) VALUES (?,?)";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, name);
      ps.setString(2, value);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add environment param " + name);
      }

      LOG.info("added environment param '{}': {}", name, value);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addEnvParam

  void addPublisher(PublisherEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    final String sql = "INSERT INTO PUBLISHER (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";

    try {
      int id = (int) datasource.getMax(null, "PUBLISHER", "ID");
      dbEntry.getIdent().setId(id + 1);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }

    String name = dbEntry.getIdent().getName();
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setInt(idx++, dbEntry.getIdent().getId());
      ps.setString(idx++, name);
      ps.setString(idx++, dbEntry.getType());
      String conf = dbEntry.getConf();
      ps.setString(idx++, conf);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add publisher " + dbEntry.getIdent());
      }

      LOG.info("added publisher '{}': {}", dbEntry.getIdent(), dbEntry);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addPublisher

  void addPublisherToCa(NameId publisher, NameId ca) throws CaMgmtException {
    final String sql = "INSERT INTO CA_HAS_PUBLISHER (CA_ID,PUBLISHER_ID) VALUES (?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setInt(1, ca.getId());
      ps.setInt(2, publisher.getId());
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add publisher " + publisher + " to CA " + ca);
      }

      LOG.info("added publisher '{}' to CA '{}'", publisher, ca);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addPublisherToCa

  void changeCa(ChangeCaEntry changeCaEntry, SecurityFactory securityFactory)
      throws CaMgmtException {
    ParamUtil.requireNonNull("changeCaEntry", changeCaEntry);
    ParamUtil.requireNonNull("securityFactory", securityFactory);
    if (!(changeCaEntry instanceof X509ChangeCaEntry)) {
      throw new CaMgmtException("unsupported ChangeCAEntry " + changeCaEntry.getClass().getName());
    }

    X509ChangeCaEntry entry = (X509ChangeCaEntry) changeCaEntry;
    X509Certificate cert = entry.getCert();
    if (cert != null) {
      boolean anyCertIssued;
      try {
        anyCertIssued = datasource.columnExists(null, "CERT", "CA_ID", entry.getIdent().getId());
      } catch (DataAccessException ex) {
        throw new CaMgmtException(ex);
      }

      if (anyCertIssued) {
        throw new CaMgmtException(
            "Cannot change the certificate of CA, since it has issued certificates");
      }
    }

    Integer serialNoBitLen = entry.getSerialNoBitLen();
    CaStatus status = entry.getStatus();
    List<String> crlUris = entry.getCrlUris();
    List<String> deltaCrlUris = entry.getDeltaCrlUris();
    List<String> ocspUris = entry.getOcspUris();
    List<String> caCertUris = entry.getCaCertUris();
    CertValidity maxValidity = entry.getMaxValidity();
    String signerType = entry.getSignerType();
    String signerConf = entry.getSignerConf();
    String crlsignerName = entry.getCrlSignerName();
    String responderName = entry.getResponderName();
    String cmpcontrolName = entry.getCmpControlName();
    Boolean duplicateKeyPermitted = entry.getDuplicateKeyPermitted();
    Boolean duplicateSubjectPermitted = entry.getDuplicateSubjectPermitted();
    Boolean saveReq = entry.getSaveRequest();
    Integer permission = entry.getPermission();
    Integer numCrls = entry.getNumCrls();
    Integer expirationPeriod = entry.getExpirationPeriod();
    Integer keepExpiredCertInDays = entry.getKeepExpiredCertInDays();
    ValidityMode validityMode = entry.getValidityMode();
    ConfPairs extraControl = entry.getExtraControl();

    if (signerType != null || signerConf != null || cert != null) {
      final String sql = "SELECT SIGNER_TYPE,CERT,SIGNER_CONF FROM CA WHERE ID=?";
      PreparedStatement stmt = null;
      ResultSet rs = null;

      try {
        stmt = prepareStatement(sql);
        stmt.setInt(1, entry.getIdent().getId());
        rs = stmt.executeQuery();
        if (!rs.next()) {
          throw new CaMgmtException("unknown CA '" + entry.getIdent());
        }

        String tmpSignerType = rs.getString("SIGNER_TYPE");
        String tmpSignerConf = rs.getString("SIGNER_CONF");
        String tmpB64Cert = rs.getString("CERT");
        if (signerType != null) {
          tmpSignerType = signerType;
        }

        if (signerConf != null) {
          tmpSignerConf = getRealString(signerConf);

          if (tmpSignerConf != null) {
            tmpSignerConf = CaManagerImpl.canonicalizeSignerConf(tmpSignerType,
                tmpSignerConf, null, securityFactory);
          }
        }

        X509Certificate tmpCert;
        if (cert != null) {
          tmpCert = cert;
        } else {
          try {
            tmpCert = X509Util.parseBase64EncodedCert(tmpB64Cert);
          } catch (CertificateException ex) {
            throw new CaMgmtException("could not parse the stored certificate for CA '"
                + changeCaEntry.getIdent() + "'" + ex.getMessage(), ex);
          }
        }

        try {
          List<String[]> signerConfs = CaEntry.splitCaSignerConfs(tmpSignerConf);
          for (String[] m : signerConfs) {
            securityFactory.createSigner(tmpSignerType, new SignerConf(m[1]), tmpCert);
          }
        } catch (XiSecurityException | ObjectCreationException ex) {
          throw new CaMgmtException(
              "could not create signer for CA '" + changeCaEntry.getIdent()
              + "'" + ex.getMessage(), ex);
        }
      } catch (SQLException ex) {
        throw new CaMgmtException(datasource, sql, ex);
      } finally {
        datasource.releaseResources(stmt, rs);
      }
    } // end if (signerType)

    StringBuilder sqlBuilder = new StringBuilder();
    sqlBuilder.append("UPDATE CA SET ");

    AtomicInteger index = new AtomicInteger(1);

    Integer idxSnSize = addToSqlIfNotNull(sqlBuilder, index, serialNoBitLen, "SN_SIZE");
    Integer idxStatus = addToSqlIfNotNull(sqlBuilder, index, status, "STATUS");
    Integer idxSubject = addToSqlIfNotNull(sqlBuilder, index, cert, "SUBJECT");
    Integer idxCert = addToSqlIfNotNull(sqlBuilder, index, cert, "CERT");
    Integer idxCrlUris = addToSqlIfNotNull(sqlBuilder, index, crlUris, "CRL_URIS");
    Integer idxDeltaCrlUris = addToSqlIfNotNull(sqlBuilder, index, deltaCrlUris, "DELTACRL_URIS");
    Integer idxOcspUris = addToSqlIfNotNull(sqlBuilder, index, ocspUris, "OCSP_URIS");
    Integer idxCaCertUris = addToSqlIfNotNull(sqlBuilder, index, caCertUris, "CACERT_URIS");
    Integer idxMaxValidity = addToSqlIfNotNull(sqlBuilder, index, maxValidity, "MAX_VALIDITY");
    Integer idxSignerType = addToSqlIfNotNull(sqlBuilder, index, signerType, "SIGNER_TYPE");
    Integer idxCrlsignerName = addToSqlIfNotNull(sqlBuilder, index, crlsignerName,
        "CRLSIGNER_NAME");
    Integer idxResponderName = addToSqlIfNotNull(sqlBuilder, index, responderName,
        "RESPONDER_NAME");
    Integer idxCmpcontrolName = addToSqlIfNotNull(sqlBuilder, index, cmpcontrolName,
        "CMPCONTROL_NAME");
    Integer idxDuplicateKey = addToSqlIfNotNull(sqlBuilder, index, duplicateKeyPermitted,
        "DUPLICATE_KEY");
    Integer idxDuplicateSubject = addToSqlIfNotNull(sqlBuilder, index, duplicateKeyPermitted,
        "DUPLICATE_SUBJECT");
    Integer idxSaveReq = addToSqlIfNotNull(sqlBuilder, index, saveReq, "SAVE_REQ");
    Integer idxPermission = addToSqlIfNotNull(sqlBuilder, index, permission, "PERMISSION");
    Integer idxNumCrls = addToSqlIfNotNull(sqlBuilder, index, numCrls, "NUM_CRLS");
    Integer idxExpirationPeriod = addToSqlIfNotNull(sqlBuilder, index, expirationPeriod,
        "EXPIRATION_PERIOD");
    Integer idxExpiredCerts = addToSqlIfNotNull(sqlBuilder, index, keepExpiredCertInDays,
         "KEEP_EXPIRED_CERT_DAYS");
    Integer idxValidityMode = addToSqlIfNotNull(sqlBuilder, index, validityMode, "VALIDITY_MODE");
    Integer idxExtraControl = addToSqlIfNotNull(sqlBuilder, index, extraControl, "EXTRA_CONTROL");
    Integer idxSignerConf = addToSqlIfNotNull(sqlBuilder, index, signerConf, "SIGNER_CONF");

    // delete the last ','
    sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
    sqlBuilder.append(" WHERE ID=?");

    if (index.get() == 1) {
      throw new IllegalArgumentException("nothing to change");
    }
    int idxId = index.get();

    final String sql = sqlBuilder.toString();
    StringBuilder sb = new StringBuilder();
    PreparedStatement ps = null;

    try {
      ps = prepareStatement(sql);

      if (idxSnSize != null) {
        sb.append("sn_size: '").append(serialNoBitLen).append("'; ");
        ps.setInt(idxSnSize, serialNoBitLen.intValue());
      }

      if (idxStatus != null) {
        sb.append("status: '").append(status.name()).append("'; ");
        ps.setString(idxStatus, status.name());
      }

      if (idxCert != null) {
        String subject = X509Util.getRfc4519Name(cert.getSubjectX500Principal());
        sb.append("cert: '").append(subject).append("'; ");
        ps.setString(idxSubject, subject);
        String base64Cert = Base64.encodeToString(cert.getEncoded());
        ps.setString(idxCert, base64Cert);
      }

      if (idxCrlUris != null) {
        String txt = StringUtil.collectionAsStringByComma(crlUris);
        sb.append("crlUri: '").append(txt).append("'; ");
        ps.setString(idxCrlUris, txt);
      }

      if (idxDeltaCrlUris != null) {
        String txt = StringUtil.collectionAsStringByComma(deltaCrlUris);
        sb.append("deltaCrlUri: '").append(txt).append("'; ");
        ps.setString(idxDeltaCrlUris, txt);
      }

      if (idxOcspUris != null) {
        String txt = StringUtil.collectionAsStringByComma(ocspUris);
        sb.append("ocspUri: '").append(txt).append("'; ");
        ps.setString(idxOcspUris, txt);
      }

      if (idxCaCertUris != null) {
        String txt = StringUtil.collectionAsStringByComma(caCertUris);
        sb.append("caCertUri: '").append(txt).append("'; ");
        ps.setString(idxCaCertUris, txt);
      }

      if (idxMaxValidity != null) {
        String txt = maxValidity.toString();
        sb.append("maxValidity: '").append(txt).append("'; ");
        ps.setString(idxMaxValidity, txt);
      }

      if (idxSignerType != null) {
        sb.append("signerType: '").append(signerType).append("'; ");
        ps.setString(idxSignerType, signerType);
      }

      if (idxSignerConf != null) {
        sb.append("signerConf: '").append(SignerConf.toString(signerConf, false, true))
          .append("'; ");
        ps.setString(idxSignerConf, signerConf);
      }

      if (idxCrlsignerName != null) {
        String txt = getRealString(crlsignerName);
        sb.append("crlSigner: '").append(txt).append("'; ");
        ps.setString(idxCrlsignerName, txt);
      }

      if (idxResponderName != null) {
        String txt = getRealString(responderName);
        sb.append("responder: '").append(txt).append("'; ");
        ps.setString(idxResponderName, txt);
      }

      if (idxCmpcontrolName != null) {
        String txt = getRealString(cmpcontrolName);
        sb.append("cmpControl: '").append(txt).append("'; ");
        ps.setString(idxCmpcontrolName, txt);
      }

      if (idxDuplicateKey != null) {
        sb.append("duplicateKey: '").append(duplicateKeyPermitted).append("'; ");
        setBoolean(ps, idxDuplicateKey, duplicateKeyPermitted);
      }

      if (idxDuplicateSubject != null) {
        sb.append("duplicateSubject: '").append(duplicateSubjectPermitted).append("'; ");
        setBoolean(ps, idxDuplicateSubject, duplicateSubjectPermitted);
      }

      if (idxSaveReq != null) {
        sb.append("saveReq: '").append(saveReq).append("'; ");
        setBoolean(ps, idxSaveReq, saveReq);
      }

      if (idxPermission != null) {
        sb.append("permission: '").append(permission).append("'; ");
        ps.setInt(idxPermission, permission);
      }

      if (idxNumCrls != null) {
        sb.append("numCrls: '").append(numCrls).append("'; ");
        ps.setInt(idxNumCrls, numCrls);
      }

      if (idxExpirationPeriod != null) {
        sb.append("expirationPeriod: '").append(expirationPeriod).append("'; ");
        ps.setInt(idxExpirationPeriod, expirationPeriod);
      }

      if (idxExpiredCerts != null) {
        sb.append("keepExpiredCertDays: '").append(keepExpiredCertInDays).append("'; ");
        ps.setInt(idxExpiredCerts, keepExpiredCertInDays);
      }

      if (idxValidityMode != null) {
        String txt = validityMode.name();
        sb.append("validityMode: '").append(txt).append("'; ");
        ps.setString(idxValidityMode, txt);
      }

      if (idxExtraControl != null) {
        sb.append("extraControl: '").append(extraControl).append("'; ");
        ps.setString(idxExtraControl, extraControl.getEncoded());
      }

      ps.setInt(idxId, changeCaEntry.getIdent().getId());
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not change CA " + entry.getIdent());
      }

      if (sb.length() > 0) {
        sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
      }

      LOG.info("changed CA '{}': {}", changeCaEntry.getIdent(), sb);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } catch (CertificateEncodingException ex) {
      throw new CaMgmtException(ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method changeCa

  void commitNextCrlNoIfLess(NameId ca, long nextCrlNo) throws CaMgmtException {
    PreparedStatement ps = null;
    try {
      final String sql = sqls.sqlNextSelectCrlNo;
      ResultSet rs = null;
      long nextCrlNoInDb;

      try {
        ps = prepareStatement(sql);
        ps.setInt(1, ca.getId());
        rs = ps.executeQuery();
        rs.next();
        nextCrlNoInDb = rs.getLong("NEXT_CRLNO");
      } catch (SQLException ex) {
        throw new CaMgmtException(datasource, sql, ex);
      } finally {
        datasource.releaseResources(ps, rs);
      }

      if (nextCrlNoInDb < nextCrlNo) {
        final String updateSql = "UPDATE CA SET NEXT_CRLNO=? WHERE ID=?";
        try {
          ps = prepareStatement(updateSql);
          ps.setLong(1, nextCrlNo);
          ps.setInt(2, ca.getId());
          ps.executeUpdate();
        } catch (SQLException ex) {
          throw new CaMgmtException(datasource, sql, ex);
        }
      }
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method commitNextCrlNoIfLess

  IdentifiedX509Certprofile changeCertprofile(NameId nameId, String type,
      String conf, CaManagerImpl caManager) throws CaMgmtException {
    ParamUtil.requireNonNull("nameId", nameId);
    ParamUtil.requireNonNull("caManager", caManager);

    StringBuilder sqlBuilder = new StringBuilder();
    sqlBuilder.append("UPDATE PROFILE SET ");

    AtomicInteger index = new AtomicInteger(1);

    StringBuilder sb = new StringBuilder();

    String tmpType = type;
    String tmpConf = conf;

    if (tmpType != null) {
      sb.append("type: '").append(tmpType).append("'; ");
    }
    if (tmpConf != null) {
      sb.append("conf: '").append(tmpConf).append("'; ");
    }

    Integer idxType = addToSqlIfNotNull(sqlBuilder, index, tmpType, "TYPE");
    Integer idxConf = addToSqlIfNotNull(sqlBuilder, index, tmpConf, "CONF");
    sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
    sqlBuilder.append(" WHERE ID=?");
    if (index.get() == 1) {
      throw new IllegalArgumentException("nothing to change");
    }

    CertprofileEntry currentDbEntry = createCertprofile(nameId.getName());
    if (tmpType == null) {
      tmpType = currentDbEntry.getType();
    }
    if (tmpConf == null) {
      tmpConf = currentDbEntry.getConf();
    }

    tmpType = getRealString(tmpType);
    tmpConf = getRealString(tmpConf);

    CertprofileEntry newDbEntry = new CertprofileEntry(currentDbEntry.getIdent(),
        tmpType, tmpConf);
    IdentifiedX509Certprofile profile = caManager.createCertprofile(newDbEntry);
    if (profile == null) {
      throw new CaMgmtException("could not create CertProfile object");
    }

    final String sql = sqlBuilder.toString();

    boolean failed = true;
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      if (idxType != null) {
        ps.setString(idxType, tmpType);
      }

      if (idxConf != null) {
        ps.setString(idxConf, getRealString(tmpConf));
      }

      ps.setInt(index.get(), nameId.getId());
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not change profile " + nameId);
      }

      if (sb.length() > 0) {
        sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
      }

      LOG.info("changed profile '{}': {}", nameId, sb);
      failed = false;
      return profile;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
      if (failed) {
        profile.shutdown();
      }
    }
  } // method changeCertprofile

  CmpControl changeCmpControl(String name, String conf) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    if (conf == null) {
      throw new IllegalArgumentException("nothing to change");
    }

    CmpControlEntry newDbEntry = new CmpControlEntry(name, conf);
    CmpControl cmpControl;
    try {
      cmpControl = new CmpControl(newDbEntry);
    } catch (InvalidConfException ex) {
      throw new CaMgmtException(ex);
    }

    final String sql = "UPDATE CMPCONTROL SET CONF=? WHERE NAME=?";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, conf);
      ps.setString(2, name);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not CMP control " + name);
      }

      LOG.info("changed CMP control '{}': {}", name, conf);
      return cmpControl;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method changeCmpControl

  RequestorEntryWrapper changeRequestor(NameId nameId, String base64Cert)
      throws CaMgmtException {
    ParamUtil.requireNonNull("nameId", nameId);

    RequestorEntry newDbEntry = new RequestorEntry(nameId, base64Cert);
    RequestorEntryWrapper requestor = new RequestorEntryWrapper();
    requestor.setDbEntry(newDbEntry);

    final String sql = "UPDATE REQUESTOR SET CERT=? WHERE ID=?";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      String b64Cert = getRealString(base64Cert);
      ps.setString(1, b64Cert);
      ps.setInt(2, nameId.getId());
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not change requestor " + nameId);
      }

      String subject = null;
      if (b64Cert != null) {
        try {
          subject = canonicalizName(
              X509Util.parseBase64EncodedCert(b64Cert).getSubjectX500Principal());
        } catch (CertificateException ex) {
          subject = "ERROR";
        }
      }
      LOG.info("changed requestor '{}': {}", nameId, subject);
      return requestor;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method changeRequestor

  ResponderEntryWrapper changeResponder(String name, String type, String conf,
      String base64Cert, CaManagerImpl caManager, SecurityFactory securityFactory)
      throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonNull("caManager", caManager);

    StringBuilder sqlBuilder = new StringBuilder();
    sqlBuilder.append("UPDATE RESPONDER SET ");

    AtomicInteger index = new AtomicInteger(1);
    Integer idxType = addToSqlIfNotNull(sqlBuilder, index, type, "TYPE");
    Integer idxCert = addToSqlIfNotNull(sqlBuilder, index, base64Cert, "CERT");
    Integer idxConf = addToSqlIfNotNull(sqlBuilder, index, conf, "CONF");
    sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
    sqlBuilder.append(" WHERE NAME=?");

    if (index.get() == 1) {
      throw new IllegalArgumentException("nothing to change");
    }

    ResponderEntry dbEntry = createResponder(name);

    String tmpType = (type != null) ? type : dbEntry.getType();
    String tmpConf;
    if (conf == null) {
      tmpConf = dbEntry.getConf();
    } else {
      tmpConf = CaManagerImpl.canonicalizeSignerConf(tmpType, conf, null, securityFactory);
    }

    String tmpBase64Cert;
    if (base64Cert == null) {
      tmpBase64Cert = dbEntry.getBase64Cert();
    } else {
      tmpBase64Cert = base64Cert;
    }

    ResponderEntry newDbEntry = new ResponderEntry(name, tmpType,
        tmpConf, tmpBase64Cert);
    ResponderEntryWrapper responder = caManager.createResponder(newDbEntry);

    final String sql = sqlBuilder.toString();

    StringBuilder sb = new StringBuilder();

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      if (idxType != null) {
        String txt = tmpType;
        ps.setString(idxType, txt);
        sb.append("type: '").append(txt).append("'; ");
      }

      if (idxConf != null) {
        String txt = getRealString(tmpConf);
        sb.append("conf: '").append(SignerConf.toString(txt, false, true));
        ps.setString(idxConf, txt);
      }

      if (idxCert != null) {
        String txt = getRealString(tmpBase64Cert);
        sb.append("cert: '");
        if (txt == null) {
          sb.append("null");
        } else {
          try {
            String subject = canonicalizName(
                X509Util.parseBase64EncodedCert(txt).getSubjectX500Principal());
            sb.append(subject);
          } catch (CertificateException ex) {
            sb.append("ERROR");
          }
        }
        sb.append("'; ");
        ps.setString(idxCert, txt);
      }

      ps.setString(index.get(), name);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not change responder " + name);
      }

      if (sb.length() > 0) {
        sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
      }
      LOG.info("changed responder: {}", sb);
      return responder;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method changeResponder

  X509CrlSignerEntryWrapper changeCrlSigner(String name, String signerType, String signerConf,
      String base64Cert, String crlControl, CaManagerImpl caManager,
      SecurityFactory securityFactory) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonNull("caManager", caManager);

    StringBuilder sqlBuilder = new StringBuilder();
    sqlBuilder.append("UPDATE CRLSIGNER SET ");

    AtomicInteger index = new AtomicInteger(1);

    Integer idxSignerType = addToSqlIfNotNull(sqlBuilder, index, signerType, "SIGNER_TYPE");
    Integer idxSignerCert = addToSqlIfNotNull(sqlBuilder, index, base64Cert, "SIGNER_CERT");
    Integer idxCrlControl = addToSqlIfNotNull(sqlBuilder, index, crlControl, "CRL_CONTROL");
    Integer idxSignerConf = addToSqlIfNotNull(sqlBuilder, index, signerConf, "SIGNER_CONF");

    sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
    sqlBuilder.append(" WHERE NAME=?");

    if (index.get() == 1) {
      throw new IllegalArgumentException("nothing to change");
    }

    X509CrlSignerEntry dbEntry = createCrlSigner(name);

    String tmpSignerType = (signerType == null) ? dbEntry.getType() : signerType;
    String tmpCrlControl = crlControl;

    String tmpSignerConf;
    String tmpBase64Cert;

    if ("CA".equalsIgnoreCase(tmpSignerType)) {
      tmpSignerConf = null;
      tmpBase64Cert = null;
    } else {
      if (signerConf == null) {
        tmpSignerConf = dbEntry.getConf();
      } else {
        tmpSignerConf = CaManagerImpl.canonicalizeSignerConf(tmpSignerType,
            signerConf, null, securityFactory);
      }

      if (base64Cert == null) {
        tmpBase64Cert = dbEntry.getBase64Cert();
      } else {
        tmpBase64Cert = base64Cert;
      }
    }

    if (tmpCrlControl == null) {
      tmpCrlControl = dbEntry.crlControl();
    } else {
      // validate crlControl
      try {
        new CrlControl(tmpCrlControl);
      } catch (InvalidConfException ex) {
        throw new CaMgmtException(concat("invalid CRL control '", tmpCrlControl, "'"));
      }
    }

    try {
      dbEntry = new X509CrlSignerEntry(name, tmpSignerType, tmpSignerConf,
          tmpBase64Cert, tmpCrlControl);
    } catch (InvalidConfException ex) {
      throw new CaMgmtException(ex);
    }
    X509CrlSignerEntryWrapper crlSigner = caManager.createX509CrlSigner(dbEntry);

    final String sql = sqlBuilder.toString();

    PreparedStatement ps = null;
    try {
      StringBuilder sb = new StringBuilder();

      ps = prepareStatement(sql);

      if (idxSignerType != null) {
        sb.append("signerType: '").append(tmpSignerType).append("'; ");
        ps.setString(idxSignerType, tmpSignerType);
      }

      if (idxSignerConf != null) {
        String txt = getRealString(tmpSignerConf);
        sb.append("signerConf: '").append(SignerConf.toString(txt, false, true))
          .append("'; ");
        ps.setString(idxSignerConf, txt);
      }

      if (idxSignerCert != null) {
        String txt = getRealString(tmpBase64Cert);
        String subject = null;
        if (txt != null) {
          try {
            subject = canonicalizName(
                X509Util.parseBase64EncodedCert(txt).getSubjectX500Principal());
          } catch (CertificateException ex) {
            subject = "ERROR";
          }
        }
        sb.append("signerCert: '").append(subject).append("'; ");
        ps.setString(idxSignerCert, txt);
      }

      if (idxCrlControl != null) {
        sb.append("crlControl: '").append(tmpCrlControl).append("'; ");
        ps.setString(idxCrlControl, tmpCrlControl);
      }

      ps.setString(index.get(), name);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not change CRL signer " + name);
      }

      if (sb.length() > 0) {
        sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
      }
      LOG.info("changed CRL signer '{}': {}", name, sb);
      return crlSigner;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method changeCrlSigner

  ScepImpl changeScep(String name, NameId caIdent, Boolean active, String responderName,
      Set<String> certProfiles, String control, CaManagerImpl caManager,
      final SecurityFactory securityFactory) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonNull("caManager", caManager);

    StringBuilder sqlBuilder = new StringBuilder();
    sqlBuilder.append("UPDATE SCEP SET ");

    AtomicInteger index = new AtomicInteger(1);
    Integer idxCa = addToSqlIfNotNull(sqlBuilder, index, caIdent, "CA_ID");
    Integer idxActive = addToSqlIfNotNull(sqlBuilder, index, active, "ACTIVE");
    Integer idxName = addToSqlIfNotNull(sqlBuilder, index, responderName, "RESPONDER_NAME");
    Integer idxProfiles = addToSqlIfNotNull(sqlBuilder, index, certProfiles, "PROFILES");
    Integer idxControl = addToSqlIfNotNull(sqlBuilder, index, control, "CONTROL");
    sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
    sqlBuilder.append(" WHERE NAME=?");

    if (index.get() == 1) {
      throw new IllegalArgumentException("nothing to change");
    }

    ScepEntry dbEntry = getScep(name, caManager.idNameMap());

    boolean tmpActive = (active == null) ? dbEntry.isActive() : active;

    String tmpResponderName = (responderName ==  null)
        ? dbEntry.getResponderName() : responderName;

    NameId tmpCaIdent;
    if (caIdent == null) {
      tmpCaIdent = dbEntry.getCaIdent();
    } else {
      tmpCaIdent = caIdent;
    }

    Set<String> tmpCertProfiles;
    if (certProfiles == null) {
      tmpCertProfiles = dbEntry.getCertProfiles();
    } else {
      tmpCertProfiles = certProfiles;
    }

    String tmpControl;
    if (control == null) {
      tmpControl = dbEntry.getControl();
    } else if (CaManager.NULL.equals(control)) {
      tmpControl = null;
    } else {
      tmpControl = control;
    }

    ScepEntry newDbEntry;
    try {
      newDbEntry = new ScepEntry(name, tmpCaIdent, tmpActive, tmpResponderName, tmpCertProfiles,
          tmpControl);
    } catch (InvalidConfException ex) {
      throw new CaMgmtException(ex);
    }
    ScepImpl scep = new ScepImpl(newDbEntry, caManager);
    final String sql = sqlBuilder.toString();
    StringBuilder sb = new StringBuilder();
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      if (idxActive != null) {
        setBoolean(ps, idxActive, tmpActive);
        sb.append("active: '").append(tmpActive).append("'; ");
      }

      if (idxCa != null) {
        sb.append("ca: '").append(caIdent).append("'; ");
        ps.setInt(idxCa, caIdent.getId());
      }

      if (idxName != null) {
        String txt = getRealString(tmpResponderName);
        ps.setString(idxName, txt);
        sb.append("responder type: '").append(txt).append("'; ");
      }

      if (idxProfiles != null) {
        sb.append("profiles: '").append(certProfiles).append("'; ");
        ps.setString(idxProfiles, StringUtil.collectionAsStringByComma(certProfiles));
      }

      if (idxControl != null) {
        String txt = getRealString(tmpControl);
        sb.append("control: '").append(tmpControl);
        ps.setString(idxControl, txt);
      }

      if (idxCa != null) {
        sb.append("ca: ").append(caIdent);
        ps.setInt(idxCa, caIdent.getId());
      }

      ps.setString(index.get(), name);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not change SCEP " + name);
      }

      final int sbLen = sb.length();
      if (sbLen > 0) {
        sb.delete(sbLen - 2, sbLen);
      }
      LOG.info("changed SCEP: {}", sb);
      return scep;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method changeScep

  void changeEnvParam(String name, String value) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonNull("value", value);

    if (CaManagerImpl.ENV_EPOCH.equalsIgnoreCase(name)) {
      throw new CaMgmtException(concat("environment ", name, " is reserved"));
    }

    final String sql = "UPDATE ENVIRONMENT SET VALUE2=? WHERE NAME=?";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, getRealString(value));
      ps.setString(2, name);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not change environment param " + name);
      }

      LOG.info("changed environment param '{}': {}", name, value);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method changeEnvParam

  IdentifiedX509CertPublisher changePublisher(String name, String type,
      String conf, CaManagerImpl caManager) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonNull("caManager", caManager);

    StringBuilder sqlBuilder = new StringBuilder();
    sqlBuilder.append("UPDATE PUBLISHER SET ");

    String tmpType = type;
    String tmpConf = conf;

    AtomicInteger index = new AtomicInteger(1);
    Integer idxType = addToSqlIfNotNull(sqlBuilder, index, tmpType, "TYPE");
    Integer idxConf = addToSqlIfNotNull(sqlBuilder, index, tmpConf, "CONF");
    sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
    sqlBuilder.append(" WHERE NAME=?");

    if (index.get() == 1) {
      throw new IllegalArgumentException("nothing to change");
    }

    PublisherEntry currentDbEntry = createPublisher(name);
    if (tmpType == null) {
      tmpType = currentDbEntry.getType();
    }

    if (tmpConf == null) {
      tmpConf = currentDbEntry.getConf();
    }

    PublisherEntry dbEntry = new PublisherEntry(currentDbEntry.getIdent(), tmpType, tmpConf);
    IdentifiedX509CertPublisher publisher = caManager.createPublisher(dbEntry);
    if (publisher == null) {
      throw new CaMgmtException("could not create publisher object");
    }

    final String sql = sqlBuilder.toString();

    PreparedStatement ps = null;
    try {
      StringBuilder sb = new StringBuilder();
      ps = prepareStatement(sql);
      if (idxType != null) {
        sb.append("type: '").append(tmpType).append("'; ");
        ps.setString(idxType, tmpType);
      }

      if (idxConf != null) {
        String txt = getRealString(tmpConf);
        sb.append("conf: '").append(txt).append("'; ");
        ps.setString(idxConf, getRealString(tmpConf));
      }

      ps.setString(index.get(), name);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not change publisher " + name);
      }

      if (sb.length() > 0) {
        sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
      }
      LOG.info("changed publisher '{}': {}", name, sb);
      return publisher;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method changePublisher

  void removeCa(String caName) throws CaMgmtException {
    ParamUtil.requireNonBlank("caName", caName);
    final String sql = "DELETE FROM CA WHERE NAME=?";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, caName);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not delelted CA " + caName);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeCa

  void removeCaAlias(String aliasName) throws CaMgmtException {
    ParamUtil.requireNonBlank("aliasName", aliasName);
    final String sql = "DELETE FROM CAALIAS WHERE NAME=?";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, aliasName);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not remove CA Alias " + aliasName);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeCaAlias

  void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException {
    ParamUtil.requireNonBlank("profileName", profileName);
    ParamUtil.requireNonBlank("caName", caName);

    int caId = getNonNullIdForName(sqls.sqlSelectCaId, caName);
    int profileId = getNonNullIdForName(sqls.sqlSelectProfileId, profileName);
    final String sql = "DELETE FROM CA_HAS_PROFILE WHERE CA_ID=? AND PROFILE_ID=?";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setInt(1, caId);
      ps.setInt(2, profileId);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException(
            "could not remove profile " + profileName + " from CA " + caName);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeCertprofileFromCa

  void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException {
    ParamUtil.requireNonBlank("requestorName", requestorName);
    ParamUtil.requireNonBlank("caName", caName);

    int caId = getNonNullIdForName(sqls.sqlSelectCaId, caName);
    int requestorId = getNonNullIdForName(sqls.sqlSelectRequestorId, requestorName);
    final String sql = "DELETE FROM CA_HAS_REQUESTOR WHERE CA_ID=? AND REQUESTOR_ID=?";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setInt(1, caId);
      ps.setInt(2, requestorId);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException(
            "could not remove requestor " + requestorName + " from CA " + caName);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeRequestorFromCa

  void removePublisherFromCa(String publisherName, String caName) throws CaMgmtException {
    ParamUtil.requireNonBlank("publisherName", publisherName);
    ParamUtil.requireNonBlank("caName", caName);
    int caId = getNonNullIdForName(sqls.sqlSelectCaId, caName);
    int publisherId = getNonNullIdForName(sqls.sqlSelectPublisherId, publisherName);

    final String sql = "DELETE FROM CA_HAS_PUBLISHER WHERE CA_ID=? AND PUBLISHER_ID=?";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setInt(1, caId);
      ps.setInt(2, publisherId);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException(
            "could not remove publisher " + publisherName + " from CA " + caName);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removePublisherFromCa

  void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException {
    ParamUtil.requireNonBlank("caName", caName);
    ParamUtil.requireNonNull("revocationInfo", revocationInfo);
    String sql = "UPDATE CA SET REV=?,RR=?,RT=?,RIT=? WHERE NAME=?";
    PreparedStatement ps = null;
    try {
      if (revocationInfo.getInvalidityTime() == null) {
        revocationInfo.setInvalidityTime(revocationInfo.getRevocationTime());
      }

      ps = prepareStatement(sql);
      int idx = 1;
      setBoolean(ps, idx++, true);
      ps.setInt(idx++, revocationInfo.getReason().getCode());
      ps.setLong(idx++, revocationInfo.getRevocationTime().getTime() / 1000);
      ps.setLong(idx++, revocationInfo.getInvalidityTime().getTime() / 1000);
      ps.setString(idx++, caName);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not revoke CA " + caName);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method revokeCa

  void addResponder(ResponderEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    final String sql = "INSERT INTO RESPONDER (NAME,TYPE,CERT,CONF) VALUES (?,?,?,?)";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setString(idx++, dbEntry.getName());
      ps.setString(idx++, dbEntry.getType());
      ps.setString(idx++, dbEntry.getBase64Cert());
      ps.setString(idx++, dbEntry.getConf());
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add responder " + dbEntry.getName());
      }

      LOG.info("added responder: {}", dbEntry.toString(false, true));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addResponder

  void unlockCa() throws CaMgmtException {
    final String sql = "DELETE FROM SYSTEM_EVENT WHERE NAME='LOCK'";
    Statement stmt = null;
    try {
      stmt = createStatement();
      stmt.execute(sql);
      if (stmt.getUpdateCount() == 0) {
        throw new CaMgmtException("could not unlock CA");
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, null);
    }
  } // method unlockCa

  void unrevokeCa(String caName) throws CaMgmtException {
    ParamUtil.requireNonBlank("caName", caName);
    LOG.info("Unrevoking of CA '{}'", caName);

    final String sql = "UPDATE CA SET REV=?,RR=?,RT=?,RIT=? WHERE NAME=?";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      setBoolean(ps, idx++, false);
      ps.setNull(idx++, Types.INTEGER);
      ps.setNull(idx++, Types.INTEGER);
      ps.setNull(idx++, Types.INTEGER);
      ps.setString(idx++, caName);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not unrevoke CA " + caName);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method unrevokeCa

  void addScep(ScepEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    final String sql = "INSERT INTO SCEP (NAME,CA_ID,ACTIVE,PROFILES,CONTROL,RESPONDER_NAME)"
        + " VALUES (?,?,?,?,?,?)";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setString(idx++, dbEntry.getName());
      ps.setInt(idx++, dbEntry.getCaIdent().getId());
      setBoolean(ps, idx++, dbEntry.isActive());
      ps.setString(idx++, StringUtil.collectionAsStringByComma(dbEntry.getCertProfiles()));
      ps.setString(idx++, dbEntry.getControl());
      ps.setString(idx++, dbEntry.getResponderName());

      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add SCEP " + dbEntry.getName());
      }

      LOG.info("added SCEP '{}': {}", dbEntry.getName(), dbEntry);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addScep

  void removeScep(String name) throws CaMgmtException {
    ParamUtil.requireNonNull("name", name);
    final String sql = "DELETE FROM SCEP WHERE NAME=?";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, name);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not remove SCEP " + name);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeScep

  ScepEntry getScep(String name, CaIdNameMap idNameMap) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    final String sql = sqls.sqlSelectScep;
    ResultSet rs = null;
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      ps.setString(1, name);
      rs = ps.executeQuery();
      if (!rs.next()) {
        throw new CaMgmtException("unknown SCEP " + name);
      }

      int caId = rs.getInt("CA_ID");
      boolean active = rs.getBoolean("ACTIVE");
      String profilesText = rs.getString("PROFILES");
      String control = rs.getString("CONTROL");
      String responderName = rs.getString("RESPONDER_NAME");
      Set<String> profiles = StringUtil.splitByCommaAsSet(profilesText);

      return new ScepEntry(name, idNameMap.getCa(caId), active, responderName, profiles, control);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } catch (InvalidConfException ex) {
      throw new CaMgmtException(ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method getScep

  void addUser(AddUserEntry userEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("userEntry", userEntry);
    String hashedPassword = PasswordHash.createHash(userEntry.getPassword());
    addUser(userEntry.getIdent().getName(), userEntry.isActive(), hashedPassword);
  } // method addUser

  void addUser(UserEntry userEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("userEntry", userEntry);
    addUser(userEntry.getIdent().getName(), userEntry.isActive(), userEntry.getHashedPassword());
  }

  private void addUser(String name, boolean active, String hashedPassword) throws CaMgmtException {
    Integer existingId = getIdForName(sqls.sqlSelectUserId, name);
    if (existingId != null) {
      throw new CaMgmtException(concat("user named '", name, " ' already exists"));
    }

    long id;
    try {
      long maxId = datasource.getMax(null, "TUSER", "ID");
      id = maxId + 1;
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }

    final String sql = "INSERT INTO TUSER (ID,NAME,ACTIVE,PASSWORD) VALUES (?,?,?,?)";

    PreparedStatement ps = null;

    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setLong(idx++, id);
      ps.setString(idx++, name);
      setBoolean(ps, idx++, active);
      ps.setString(idx++, hashedPassword);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add user " + name);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }

    LOG.info("added user '{}'", name);
  } // method addUser

  void removeUser(String username) throws CaMgmtException {
    ParamUtil.requireNonBlank("username", username);
    final String sql = "DELETE FROM TUSER WHERE NAME=?";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, username);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not remove User " + username);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeUser

  void changeUser(ChangeUserEntry userEntry) throws CaMgmtException {
    String username = userEntry.getIdent().getName();

    Integer existingId = getIdForName(sqls.sqlSelectUserId, username);
    if (existingId == null) {
      throw new CaMgmtException(concat("user '", username, " ' does not exist"));
    }
    userEntry.getIdent().setId(existingId);

    StringBuilder sqlBuilder = new StringBuilder();
    sqlBuilder.append("UPDATE TUSER SET ");

    AtomicInteger index = new AtomicInteger(1);

    Boolean active = userEntry.getActive();
    Integer idxActive = null;
    if (active != null) {
      idxActive = index.getAndIncrement();
      sqlBuilder.append("ACTIVE=?,");
    }

    String password = userEntry.getPassword();

    Integer idxPassword = null;
    if (password != null) {
      idxPassword = index.getAndIncrement();
      sqlBuilder.append("PASSWORD=?,");
    }

    sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
    sqlBuilder.append(" WHERE ID=?");

    if (index.get() == 1) {
      throw new IllegalArgumentException("nothing to change");
    }

    final String sql = sqlBuilder.toString();

    StringBuilder sb = new StringBuilder();

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      if (idxActive != null) {
        setBoolean(ps, idxActive, active);
        sb.append("active: ").append(active).append("; ");
      }

      if (idxPassword != null) {
        String hashedPassword = PasswordHash.createHash(password);
        ps.setString(idxPassword, hashedPassword);
        sb.append("password: ****; ");
      }

      ps.setLong(index.get(), existingId);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not change user " + username);
      }

      if (sb.length() > 0) {
        sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
      }
      LOG.info("changed user: {}", sb);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method changeUser

  void removeUserFromCa(String username, String caName) throws CaMgmtException {
    Integer id = getIdForName(sqls.sqlSelectUserId, username);
    if (id == null) {
      throw new CaMgmtException("unknown user " + username);
    }

    int caId = getNonNullIdForName(sqls.sqlSelectCaId, caName);

    final String sql = "DELETE FROM CA_HAS_USER WHERE CA_ID=? AND USER_ID=?";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setInt(1, caId);
      ps.setInt(2, id);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException(
            "could not remove user " + username + " from CA " + caName);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeRequestorFromCa

  void addUserToCa(CaHasUserEntry user, NameId ca) throws CaMgmtException {
    ParamUtil.requireNonNull("user", user);
    ParamUtil.requireNonNull("ca", ca);

    final NameId userIdent = user.getUserIdent();
    Integer existingId = getIdForName(sqls.sqlSelectUserId, userIdent.getName());
    if (existingId == null) {
      throw new CaMgmtException(concat("user '", userIdent.getName(), " ' does not exist"));
    }
    userIdent.setId(existingId);

    PreparedStatement ps = null;
    final String sql = "INSERT INTO CA_HAS_USER (ID,CA_ID,USER_ID, PERMISSION,PROFILES)"
        + " VALUES (?,?,?,?,?)";

    long maxId;
    try {
      maxId = datasource.getMax(null, "CA_HAS_USER", "ID");
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }

    try {
      ps = prepareStatement(sql);

      int idx = 1;
      ps.setLong(idx++, maxId + 1);
      ps.setInt(idx++, ca.getId());
      ps.setInt(idx++, userIdent.getId());
      ps.setInt(idx++, user.getPermission());

      String profilesText = StringUtil.collectionAsStringByComma(user.getProfiles());
      ps.setString(idx++, profilesText);

      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add user " + userIdent + " to CA " + ca);
      }

      LOG.info("added user '{}' to CA '{}': permission: {}; profile: {}",
          userIdent, ca, user.getPermission(), profilesText);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addUserToCa

  Map<String, CaHasUserEntry> getCaHasUsersForUser(String user, CaIdNameMap idNameMap)
      throws CaMgmtException {
    Integer existingId = getIdForName(sqls.sqlSelectUserId, user);
    if (existingId == null) {
      throw new CaMgmtException(concat("user '", user, " ' does not exist"));
    }

    final String sql = "SELECT CA_ID,PERMISSION,PROFILES FROM CA_HAS_USER WHERE USER_ID=?";
    PreparedStatement ps = null;
    ResultSet rs = null;
    try {
      ps = prepareStatement(sql);
      ps.setInt(1, existingId);
      rs = ps.executeQuery();

      Map<String, CaHasUserEntry> ret = new HashMap<>();
      while (rs.next()) {
        int permission = rs.getInt("PERMISSION");
        String str = rs.getString("PROFILES");
        List<String> list = StringUtil.splitByComma(str);
        Set<String> profiles = (list == null) ? null : new HashSet<>(list);
        CaHasUserEntry caHasUser = new CaHasUserEntry(new NameId(existingId, user));
        caHasUser.setPermission(permission);
        caHasUser.setProfiles(profiles);

        int caId = rs.getInt("CA_ID");
        String caName = idNameMap.getCaName(caId);

        ret.put(caName, caHasUser);
      }
      return ret;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  }  // method getCaHasUsersForUser

  List<CaHasUserEntry> getCaHasUsersForCa(String caName, CaIdNameMap idNameMap)
      throws CaMgmtException {
    NameId caIdent = idNameMap.getCa(caName);
    if (caIdent == null) {
      throw new CaMgmtException("unknown CA " + caName);
    }

    final String sql = "SELECT NAME,PERMISSION,PROFILES FROM CA_HAS_USER INNER JOIN TUSER"
        + " ON CA_ID=? AND TUSER.ID=CA_HAS_USER.USER_ID";
    PreparedStatement ps = null;
    ResultSet rs = null;
    try {
      ps = prepareStatement(sql);
      ps.setInt(1, caIdent.getId().intValue());
      rs = ps.executeQuery();

      List<CaHasUserEntry> ret = new LinkedList<>();
      while (rs.next()) {
        String username = rs.getString("NAME");
        int permission = rs.getInt("PERMISSION");
        String str = rs.getString("PROFILES");
        List<String> list = StringUtil.splitByComma(str);
        Set<String> profiles = (list == null) ? null : new HashSet<>(list);
        CaHasUserEntry caHasUser = new CaHasUserEntry(new NameId(null, username));
        caHasUser.setPermission(permission);
        caHasUser.setProfiles(profiles);

        ret.add(caHasUser);
      }
      return ret;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method getCaHasUsersForCa

  UserEntry getUser(String username) throws CaMgmtException {
    return getUser(username, false);
  }

  UserEntry getUser(String username, boolean nullable) throws CaMgmtException {
    ParamUtil.requireNonNull("username", username);
    NameId ident = new NameId(null, username);

    final String sql = sqls.sqlSelectUser;
    ResultSet rs = null;
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      int idx = 1;
      ps.setString(idx++, ident.getName());
      rs = ps.executeQuery();
      if (!rs.next()) {
        if (nullable) {
          return null;
        } else {
          throw new CaMgmtException("unknown user " + username);
        }
      }

      int id = rs.getInt("ID");
      ident.setId(id);
      boolean active = rs.getBoolean("ACTIVE");
      String hashedPassword = rs.getString("PASSWORD");
      return new UserEntry(ident, active, hashedPassword);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method getUser

  private static void setBoolean(PreparedStatement ps, int index, boolean bo)
      throws SQLException {
    ps.setInt(index, bo ? 1 : 0);
  }

  private static Integer addToSqlIfNotNull(StringBuilder sqlBuilder,
      AtomicInteger index, Object columnObj, String columnName) {
    if (columnObj == null) {
      return null;
    }

    sqlBuilder.append(columnName).append("=?,");
    return index.getAndIncrement();
  }

  private static String getRealString(String str) {
    return CaManager.NULL.equalsIgnoreCase(str) ? null : str;
  }

  static String canonicalizName(X500Principal prin) {
    ParamUtil.requireNonNull("prin", prin);
    X500Name x500Name = X500Name.getInstance(prin.getEncoded());
    return X509Util.canonicalizName(x500Name);
  }

  private int getNonNullIdForName(String sql, String name) throws CaMgmtException {
    Integer id = getIdForName(sql, name);
    if (id != null) {
      return id.intValue();
    }

    throw new CaMgmtException(concat("Found no entry named ",name));
  }

  private Integer getIdForName(String sql, String name) throws CaMgmtException {
    PreparedStatement ps = null;
    ResultSet rs = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, name);
      rs = ps.executeQuery();
      if (!rs.next()) {
        return null;
      }

      return rs.getInt("ID");
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  }

  private Map<Integer, String> getIdNameMap(String tableName) throws CaMgmtException {
    final String sql = concat("SELECT ID,NAME FROM ", tableName);
    Statement ps = null;
    ResultSet rs = null;

    Map<Integer, String> ret = new HashMap<>();
    try {
      ps = createStatement();
      rs = ps.executeQuery(sql);
      while (rs.next()) {
        ret.put(rs.getInt("ID"), rs.getString("NAME"));
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }

    return ret;
  }

  private static String concat(String s1, String... strs) {
    return StringUtil.concat(s1, strs);
  }

}
