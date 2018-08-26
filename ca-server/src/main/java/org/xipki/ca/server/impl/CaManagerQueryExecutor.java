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
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.impl.SqlColumn.ColumnType;
import org.xipki.ca.server.impl.store.CertStore;
import org.xipki.ca.server.impl.util.PasswordHash;
import org.xipki.ca.server.mgmt.api.AddUserEntry;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.CaHasUserEntry;
import org.xipki.ca.server.mgmt.api.CaManager;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.ca.server.mgmt.api.ChangeCaEntry;
import org.xipki.ca.server.mgmt.api.ChangeUserEntry;
import org.xipki.ca.server.mgmt.api.CmpControl;
import org.xipki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.ca.server.mgmt.api.CrlControl;
import org.xipki.ca.server.mgmt.api.ProtocolSupport;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.api.RequestorEntry;
import org.xipki.ca.server.mgmt.api.ScepControl;
import org.xipki.ca.server.mgmt.api.SignerEntry;
import org.xipki.ca.server.mgmt.api.UserEntry;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.ConfPairs;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
class CaManagerQueryExecutor {

  private static final Logger LOG = LoggerFactory.getLogger(CaManagerQueryExecutor.class);

  private static final ColumnType INT = ColumnType.INT;
  private static final ColumnType BOOL = ColumnType.BOOL;
  private static final ColumnType STRING = ColumnType.STRING;

  private final DataSourceWrapper datasource;

  private final String sqlSelectProfileId;
  private final String sqlSelectProfile;
  private final String sqlSelectPublisherId;
  private final String sqlSelectPublisher;
  private final String sqlSelectRequestorId;
  private final String sqlSelectRequestor;
  private final String sqlSelectSigner;
  private final String sqlSelectCaId;
  private final String sqlSelectCa;
  private final String sqlNextSelectCrlNo;
  private final String sqlSelectSystemEvent;
  private final String sqlSelectUserId;
  private final String sqlSelectUser;

  CaManagerQueryExecutor(DataSourceWrapper datasource) {
    this.datasource = ParamUtil.requireNonNull("datasource", datasource);
    this.sqlSelectProfileId = buildSelectFirstSql("ID FROM PROFILE WHERE NAME=?");
    this.sqlSelectProfile = buildSelectFirstSql("ID,TYPE,CONF FROM PROFILE WHERE NAME=?");
    this.sqlSelectPublisherId = buildSelectFirstSql("ID FROM PUBLISHER WHERE NAME=?");
    this.sqlSelectPublisher = buildSelectFirstSql("ID,TYPE,CONF FROM PUBLISHER WHERE NAME=?");
    this.sqlSelectRequestorId = buildSelectFirstSql("ID FROM REQUESTOR WHERE NAME=?");
    this.sqlSelectRequestor = buildSelectFirstSql("ID,TYPE,CONF FROM REQUESTOR WHERE NAME=?");
    this.sqlSelectSigner = buildSelectFirstSql("TYPE,CERT,CONF FROM SIGNER WHERE NAME=?");
    this.sqlSelectCaId = buildSelectFirstSql("ID FROM CA WHERE NAME=?");
    this.sqlSelectCa = buildSelectFirstSql("ID,SN_SIZE,NEXT_CRLNO,STATUS,MAX_VALIDITY,CERT,"
        + "SIGNER_TYPE,CMP_RESPONDER_NAME,SCEP_RESPONDER_NAME,CRL_SIGNER_NAME,"
        + "CMP_CONTROL,CRL_CONTROL,SCEP_CONTROL,DUPLICATE_KEY,DUPLICATE_SUBJECT,PROTOCOL_SUPPORT,"
        + "SAVE_REQ,PERMISSION,NUM_CRLS,KEEP_EXPIRED_CERT_DAYS,EXPIRATION_PERIOD,REV_INFO,"
        + "VALIDITY_MODE,CA_URIS,EXTRA_CONTROL,SIGNER_CONF FROM CA WHERE NAME=?");
    this.sqlNextSelectCrlNo = buildSelectFirstSql("NEXT_CRLNO FROM CA WHERE ID=?");
    this.sqlSelectSystemEvent = buildSelectFirstSql(
        "EVENT_TIME,EVENT_OWNER FROM SYSTEM_EVENT WHERE NAME=?");
    this.sqlSelectUserId = buildSelectFirstSql("ID FROM TUSER WHERE NAME=?");
    this.sqlSelectUser = buildSelectFirstSql("ID,ACTIVE,PASSWORD FROM TUSER WHERE NAME=?");
  }

  private String buildSelectFirstSql(String coreSql) {
    return datasource.buildSelectFirstSql(1, coreSql);
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
    final String sql = sqlSelectSystemEvent;
    PreparedStatement ps = null;
    ResultSet rs = null;

    try {
      ps = prepareStatement(sql);
      ps.setString(1, eventName);
      rs = ps.executeQuery();

      if (!rs.next()) {
        return null;
      }

      return new SystemEvent(eventName, rs.getString("EVENT_OWNER"), rs.getLong("EVENT_TIME"));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method getSystemEvent

  private void deleteSystemEvent(String eventName) throws CaMgmtException {
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

  private void addSystemEvent(SystemEvent systemEvent) throws CaMgmtException {
    final String sql =
        "INSERT INTO SYSTEM_EVENT (NAME,EVENT_TIME,EVENT_TIME2,EVENT_OWNER) VALUES (?,?,?,?)";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, systemEvent.getName());
      ps.setLong(2, systemEvent.getEventTime());
      ps.setTimestamp(3, new Timestamp(systemEvent.getEventTime() * 1000L));
      ps.setString(4, systemEvent.getOwner());

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

  Map<String, Integer> createCaAliases() throws CaMgmtException {
    Map<String, Integer> map = new HashMap<>();

    final String sql = "SELECT NAME,CA_ID FROM CAALIAS";
    Statement stmt = null;
    ResultSet rs = null;

    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        map.put(rs.getString("NAME"), rs.getInt("CA_ID"));
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
    final String sql = sqlSelectProfile;
    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, name);
      rs = stmt.executeQuery();

      if (!rs.next()) {
        throw new CaMgmtException("unknown CA " + name);
      }

      return new CertprofileEntry(new NameId(rs.getInt("ID"), name),
          rs.getString("TYPE"), rs.getString("CONF"));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createCertprofile

  List<String> namesFromTable(String table) throws CaMgmtException {
    return namesFromTable(table, "NAME");
  }

  private List<String> namesFromTable(String table, String nameColumn) throws CaMgmtException {
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
    final String sql = sqlSelectPublisher;
    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, name);
      rs = stmt.executeQuery();

      if (!rs.next()) {
        throw new CaMgmtException("unkown Publisher " + name);
      }

      return new PublisherEntry(new NameId(rs.getInt("ID"), name),
          rs.getString("TYPE"), rs.getString("CONF"));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createPublisher

  Integer getRequestorId(String requestorName) throws CaMgmtException {
    final String sql = sqlSelectRequestorId;
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
    final String sql = sqlSelectRequestor;
    PreparedStatement stmt = null;
    ResultSet rs = null;

    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, name);
      rs = stmt.executeQuery();

      if (!rs.next()) {
        throw new CaMgmtException("unknown Requestor " + name);
      }

      return new RequestorEntry(new NameId(rs.getInt("ID"), name),
          rs.getString("TYPE"), rs.getString("CONF"));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createRequestor

  SignerEntry createSigner(String name) throws CaMgmtException {
    final String sql = sqlSelectSigner;
    PreparedStatement stmt = null;
    ResultSet rs = null;

    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, name);
      rs = stmt.executeQuery();

      if (!rs.next()) {
        throw new CaMgmtException("unknown signer " + name);
      }

      return new SignerEntry(name, rs.getString("TYPE"), rs.getString("CONF"),
          rs.getString("CERT"));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createResponder

  CaInfo createCaInfo(String name, boolean masterMode, CertStore certstore) throws CaMgmtException {
    final String sql = sqlSelectCa;
    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      stmt.setString(1, name);
      rs = stmt.executeQuery();

      if (!rs.next()) {
        throw new CaMgmtException("uknown CA " + name);
      }

      String caUrisText = rs.getString("CA_URIS");
      CaUris caUris = (caUrisText == null) ? null : CaUris.decode(caUrisText);
      CaEntry entry = new CaEntry(new NameId(rs.getInt("ID"), name), rs.getInt("SN_SIZE"),
          rs.getLong("NEXT_CRLNO"), rs.getString("SIGNER_TYPE"), rs.getString("SIGNER_CONF"),
          caUris, rs.getInt("NUM_CRLS"), rs.getInt("EXPIRATION_PERIOD"));
      entry.setCert(generateCert(rs.getString("CERT")));

      entry.setStatus(CaStatus.forName(rs.getString("STATUS")));
      entry.setMaxValidity(CertValidity.getInstance(rs.getString("MAX_VALIDITY")));
      entry.setKeepExpiredCertInDays(rs.getInt("KEEP_EXPIRED_CERT_DAYS"));

      String crlsignerName = rs.getString("CRL_SIGNER_NAME");
      if (StringUtil.isNotBlank(crlsignerName)) {
        entry.setCrlSignerName(crlsignerName);
      }

      String cmpResponderName = rs.getString("CMP_RESPONDER_NAME");
      if (StringUtil.isNotBlank(cmpResponderName)) {
        entry.setCmpResponderName(cmpResponderName);
      }

      String scepResponderName = rs.getString("SCEP_RESPONDER_NAME");
      if (StringUtil.isNotBlank(scepResponderName)) {
        entry.setScepResponderName(scepResponderName);
      }

      String extraControl = rs.getString("EXTRA_CONTROL");
      if (StringUtil.isNotBlank(extraControl)) {
        entry.setExtraControl(new ConfPairs(extraControl).unmodifiable());
      }

      String cmpcontrol = rs.getString("CMP_CONTROL");
      // null or blank value is allowed
      try {
        entry.setCmpControl(new CmpControl(cmpcontrol));
      } catch (InvalidConfException ex) {
        throw new CaMgmtException("invalid CMP_CONTROL: " + cmpcontrol);
      }

      String crlcontrol = rs.getString("CRL_CONTROL");
      if (StringUtil.isNotBlank(crlcontrol)) {
        try {
          entry.setCrlControl(new CrlControl(crlcontrol));
        } catch (InvalidConfException ex) {
          throw new CaMgmtException("invalid CRL_CONTROL: " + crlcontrol, ex);
        }
      }

      String scepcontrol = rs.getString("SCEP_CONTROL");
      // null or blank value is allowed
      try {
        entry.setScepControl(new ScepControl(scepcontrol));
      } catch (InvalidConfException ex) {
        throw new CaMgmtException("invalid SCEP_CONTROL: " + scepcontrol, ex);
      }

      entry.setDuplicateKeyPermitted((rs.getInt("DUPLICATE_KEY") != 0));
      entry.setDuplicateSubjectPermitted((rs.getInt("DUPLICATE_SUBJECT") != 0));
      entry.setProtocolSupport(new ProtocolSupport(rs.getString("PROTOCOL_SUPPORT")));
      entry.setSaveRequest((rs.getInt("SAVE_REQ") != 0));
      entry.setPermission(rs.getInt("PERMISSION"));

      String revInfo = rs.getString("REV_INFO");
      CertRevocationInfo revocationInfo = (revInfo == null)
          ? null : CertRevocationInfo.fromEncoded(revInfo);
      entry.setRevocationInfo(revocationInfo);

      String validityModeS = rs.getString("VALIDITY_MODE");
      entry.setValidityMode(validityModeS == null
          ? ValidityMode.STRICT : ValidityMode.forName(validityModeS));

      try {
        return new CaInfo(entry, certstore);
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

        List<String> list = StringUtil.split(rs.getString("PROFILES"), ",");
        Set<String> profiles = (list == null) ? null : new HashSet<>(list);
        CaHasRequestorEntry entry = new CaHasRequestorEntry(new NameId(id, name));
        entry.setRa(rs.getBoolean("RA"));
        entry.setPermission(rs.getInt("PERMISSION"));
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
        ret.add(rs.getInt("PROFILE_ID"));
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
        ret.add(rs.getInt("PUBLISHER_ID"));
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

  void addCa(CaEntry caEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("caEntry", caEntry);

    try {
      int id = (int) datasource.getMax(null, "CA", "ID");
      caEntry.getIdent().setId(id + 1);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }

    final String sql = "INSERT INTO CA (ID,NAME,SUBJECT,SN_SIZE,NEXT_CRLNO,STATUS,CA_URIS,"
        + "MAX_VALIDITY,CERT,SIGNER_TYPE,CRL_SIGNER_NAME,CMP_RESPONDER_NAME,SCEP_RESPONDER_NAME,"
        + "CRL_CONTROL,CMP_CONTROL,SCEP_CONTROL,DUPLICATE_KEY,DUPLICATE_SUBJECT,PROTOCOL_SUPPORT,"
        + "SAVE_REQ,PERMISSION,NUM_CRLS,EXPIRATION_PERIOD,KEEP_EXPIRED_CERT_DAYS,VALIDITY_MODE,"
        + "EXTRA_CONTROL,SIGNER_CONF) "
        + "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    // insert to table ca
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setInt(idx++, caEntry.getIdent().getId());
      ps.setString(idx++, caEntry.getIdent().getName());
      ps.setString(idx++, caEntry.getSubject());
      ps.setInt(idx++, caEntry.getSerialNoBitLen());
      ps.setLong(idx++, caEntry.getNextCrlNumber());
      ps.setString(idx++, caEntry.getStatus().getStatus());

      CaUris caUris = caEntry.getCaUris();
      ps.setString(idx++, (caUris == null) ? null : caEntry.getCaUris().getEncoded());
      ps.setString(idx++, caEntry.getMaxValidity().toString());
      byte[] encodedCert = caEntry.getCert().getEncoded();
      ps.setString(idx++, Base64.encodeToString(encodedCert));
      ps.setString(idx++, caEntry.getSignerType());
      ps.setString(idx++, caEntry.getCrlSignerName());
      ps.setString(idx++, caEntry.getCmpResponderName());
      ps.setString(idx++, caEntry.getScepResponderName());

      CrlControl crlControl = caEntry.getCrlControl();
      ps.setString(idx++, (crlControl == null ? null : crlControl.getConf()));

      CmpControl cmpControl = caEntry.getCmpControl();
      ps.setString(idx++, (cmpControl == null ? null : cmpControl.getConf()));

      ScepControl scepControl = caEntry.getScepControl();
      ps.setString(idx++, (scepControl == null ? null : scepControl.getConf()));

      setBoolean(ps, idx++, caEntry.isDuplicateKeyPermitted());
      setBoolean(ps, idx++, caEntry.isDuplicateSubjectPermitted());

      ProtocolSupport protocolSupport = caEntry.getProtocoSupport();
      ps.setString(idx++, (protocolSupport == null ? null : protocolSupport.getEncoded()));

      setBoolean(ps, idx++, caEntry.isSaveRequest());
      ps.setInt(idx++, caEntry.getPermission());
      ps.setInt(idx++, caEntry.getNumCrls());
      ps.setInt(idx++, caEntry.getExpirationPeriod());
      ps.setInt(idx++, caEntry.getKeepExpiredCertInDays());
      ps.setString(idx++, caEntry.getValidityMode().name());
      ConfPairs extraControl = caEntry.getExtraControl();
      String encodedExtraCtrl = (extraControl == null) ? null : extraControl.getEncoded();
      ps.setString(idx++, StringUtil.isBlank(encodedExtraCtrl) ? null : encodedExtraCtrl);
      ps.setString(idx++, caEntry.getSignerConf());
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add CA " + caEntry.getIdent());
      }
      if (LOG.isInfoEnabled()) {
        LOG.info("add CA '{}': {}", caEntry.getIdent(), caEntry.toString(false, true));
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
    final String sql = "INSERT INTO PROFILE (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";

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
      ps.setString(idx++, dbEntry.getType());
      String conf = dbEntry.getConf();
      ps.setString(idx++, conf);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add certprofile " + dbEntry.getIdent());
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
      ps.setString(1, name);
      ps.setString(2, dbEntry.getConf());
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

    final String sql = "INSERT INTO REQUESTOR (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setInt(1, dbEntry.getIdent().getId());
      ps.setString(2, dbEntry.getIdent().getName());
      ps.setString(3, dbEntry.getType());
      ps.setString(4, dbEntry.getConf());
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add requestor " + dbEntry.getIdent());
      }

      if (LOG.isInfoEnabled()) {
        LOG.info("added requestor '{}': {}", dbEntry.getIdent(), dbEntry.toString(false));
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addRequestor

  void addRequestorIfNeeded(String requestorName) throws CaMgmtException {
    String sql = sqlSelectRequestorId;
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

      sql = "INSERT INTO REQUESTOR (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";
      stmt = prepareStatement(sql);
      stmt.setInt(1, id + 1);
      stmt.setString(2, requestorName);
      // ANY VALUE
      stmt.setString(3, "EMBEDDED");
      // ANY VALUE
      stmt.setString(4, "DEFAULT");
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

      setBoolean(ps, idx++, requestor.isRa());
      ps.setInt(idx++, requestor.getPermission());
      String profilesText = StringUtil.collectionAsString(requestor.getProfiles(), ",");
      ps.setString(idx++, profilesText);

      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add requestor " + requestorIdent + " to CA " + ca);
      }

      LOG.info("added requestor '{}' to CA '{}': ra: {}; permission: {}; profile: {}",
          requestorIdent, ca, requestor.isRa(), requestor.getPermission(), profilesText);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addRequestorToCa

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

  void changeCa(ChangeCaEntry changeCaEntry, CaEntry currentCaEntry,
      SecurityFactory securityFactory) throws CaMgmtException {
    ParamUtil.requireNonNull("changeCaEntry", changeCaEntry);
    ParamUtil.requireNonNull("securityFactory", securityFactory);

    X509Certificate cert = changeCaEntry.getCert();
    if (cert != null) {
      boolean anyCertIssued;
      try {
        anyCertIssued = datasource.columnExists(null, "CERT", "CA_ID",
            changeCaEntry.getIdent().getId());
      } catch (DataAccessException ex) {
        throw new CaMgmtException(ex);
      }

      if (anyCertIssued) {
        throw new CaMgmtException("Cannot change certificate of CA which has issued certificates");
      }
    }

    String signerType = changeCaEntry.getSignerType();
    String signerConf = changeCaEntry.getSignerConf();

    if (signerType != null || signerConf != null || cert != null) {
      // validate the signer configuration
      final String sql = "SELECT SIGNER_TYPE,CERT,SIGNER_CONF FROM CA WHERE ID=?";
      PreparedStatement stmt = null;
      ResultSet rs = null;

      try {
        stmt = prepareStatement(sql);
        stmt.setInt(1, changeCaEntry.getIdent().getId());
        rs = stmt.executeQuery();
        if (!rs.next()) {
          throw new CaMgmtException("unknown CA '" + changeCaEntry.getIdent());
        }

        if (signerType == null) {
          signerType = rs.getString("SIGNER_TYPE");
        }

        if (signerConf == null) {
          signerConf = rs.getString("SIGNER_CONF");
        } else {
          signerConf = CaManagerImpl.canonicalizeSignerConf(
              signerType, signerConf, null, securityFactory);
        }

        // need the certificate to validity the signer
        X509Certificate tmpCert;
        if (cert != null) {
          tmpCert = cert;
        } else {
          try {
            tmpCert = X509Util.parseCert(rs.getString("CERT").getBytes());
          } catch (CertificateException ex) {
            throw new CaMgmtException("could not parse the stored certificate for CA '"
                + changeCaEntry.getIdent() + "'" + ex.getMessage(), ex);
          }
        }

        try {
          List<String[]> signerConfs = CaEntry.splitCaSignerConfs(signerConf);
          for (String[] m : signerConfs) {
            securityFactory.createSigner(signerType, new SignerConf(m[1]), tmpCert);
          }
        } catch (XiSecurityException | ObjectCreationException ex) {
          throw new CaMgmtException("could not create signer for CA '"
              + changeCaEntry.getIdent() + "'" + ex.getMessage(), ex);
        }
      } catch (SQLException ex) {
        throw new CaMgmtException(datasource, sql, ex);
      } finally {
        datasource.releaseResources(stmt, rs);
      }
    } // end if (signerType)

    String subject = null;
    String base64Cert = null;
    if (cert != null) {
      subject = X509Util.getRfc4519Name(cert.getSubjectX500Principal());
      try {
        base64Cert = Base64.encodeToString(cert.getEncoded());
      } catch (CertificateEncodingException ex) {
        throw new CaMgmtException("could not encode the certificate", ex);
      }
    }

    String status = (changeCaEntry.getStatus() == null) ? null : changeCaEntry.getStatus().name();
    String maxValidity = (changeCaEntry.getMaxValidity() == null) ? null
        : changeCaEntry.getMaxValidity().toString();
    String extraControl = (changeCaEntry.getExtraControl() == null) ? null
        : changeCaEntry.getExtraControl().getEncoded();
    String validityMode = (changeCaEntry.getValidityMode() == null) ? null
        : changeCaEntry.getValidityMode().name();

    String caUrisStr = null;
    CaUris changeUris = changeCaEntry.getCaUris();
    if (changeUris != null
        && (changeUris.getCacertUris() != null
          || changeUris.getCrlUris() != null
          || changeUris.getDeltaCrlUris() != null
          || changeUris.getOcspUris() != null)) {
      CaUris oldCaUris = currentCaEntry.getCaUris();

      List<String> uris = changeUris.getCacertUris();
      // CHECKSTYLE:SKIP
      List<String> cacertUris = (uris == null) ? oldCaUris.getCacertUris() : uris;

      uris = changeUris.getOcspUris();
      List<String> ocspUris = (uris == null) ? oldCaUris.getOcspUris() : uris;

      uris = changeUris.getCrlUris();
      List<String> crlUris = (uris == null) ? oldCaUris.getCrlUris() : uris;

      uris = changeUris.getDeltaCrlUris();
      List<String> deltaCrlUris = (uris == null) ? oldCaUris.getDeltaCrlUris() : uris;
      CaUris newCaUris = new CaUris(cacertUris, ocspUris, crlUris, deltaCrlUris);
      caUrisStr = newCaUris.getEncoded();
      if (caUrisStr.isEmpty()) {
        caUrisStr = CaManager.NULL;
      }
    }

    String protocolSupportStr = null;
    Boolean supportCmp = changeCaEntry.getSupportCmp();
    Boolean supportRest = changeCaEntry.getSupportRest();
    Boolean supportScep = changeCaEntry.getSupportScep();
    if (supportCmp != null || supportRest != null || supportScep != null) {
      ProtocolSupport oldSupport = currentCaEntry.getProtocoSupport();
      ProtocolSupport support = new ProtocolSupport(oldSupport.supportsCmp(),
          oldSupport.supportsRest(), oldSupport.supportsScep());

      if (supportCmp != null) {
        support.setCmp(supportCmp);
      }

      if (supportRest != null) {
        support.setRest(supportRest);
      }

      if (supportScep != null) {
        support.setScep(supportScep);
      }

      protocolSupportStr = support.getEncoded();
    }

    changeIfNotNull("CA", col(INT, "ID", changeCaEntry.getIdent().getId()),
        col(INT, "SN_SIZE", changeCaEntry.getSerialNoBitLen()), col(STRING, "STATUS", status),
        col(STRING, "SUBJECT", subject), col(STRING, "CERT", base64Cert),
        col(STRING, "CA_URIS", caUrisStr),
        col(STRING, "MAX_VALIDITY", maxValidity), col(STRING, "SIGNER_TYPE", signerType),
        col(STRING, "CRL_SIGNER_NAME", changeCaEntry.getCrlSignerName()),
        col(STRING, "CMP_RESPONDER_NAME", changeCaEntry.getCmpResponderName()),
        col(STRING, "SCEP_RESPONDER_NAME", changeCaEntry.getScepResponderName()),
        col(STRING, "CMP_CONTROL", changeCaEntry.getCmpControl()),
        col(STRING, "CRL_CONTROL", changeCaEntry.getCrlControl()),
        col(STRING, "SCEP_CONTROL", changeCaEntry.getScepControl()),
        col(BOOL, "DUPLICATE_KEY", changeCaEntry.getDuplicateKeyPermitted()),
        col(BOOL, "DUPLICATE_SUBJECT", changeCaEntry.getDuplicateSubjectPermitted()),
        col(STRING, "PROTOCOL_SUPPORT", protocolSupportStr),
        col(BOOL, "SAVE_REQ", changeCaEntry.getSaveRequest()),
        col(INT, "PERMISSION", changeCaEntry.getPermission()),
        col(INT, "NUM_CRLS", changeCaEntry.getNumCrls()),
        col(INT, "EXPIRATION_PERIOD", changeCaEntry.getExpirationPeriod()),
        col(INT, "KEEP_EXPIRED_CERT_DAYS", changeCaEntry.getKeepExpiredCertInDays()),
        col(STRING, "VALIDITY_MODE", validityMode),
        col(STRING, "EXTRA_CONTROL", extraControl),
        col(STRING, "SIGNER_CONF", signerConf, false, true));
  } // method changeCa

  void commitNextCrlNoIfLess(NameId ca, long nextCrlNo) throws CaMgmtException {
    PreparedStatement ps = null;
    try {
      final String sql = sqlNextSelectCrlNo;
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

  IdentifiedCertprofile changeCertprofile(NameId nameId, String type, String conf,
      CaManagerImpl caManager) throws CaMgmtException {
    CertprofileEntry currentDbEntry = createCertprofile(nameId.getName());
    CertprofileEntry newDbEntry = new CertprofileEntry(currentDbEntry.getIdent(),
        str(type, currentDbEntry.getType()), str(conf, currentDbEntry.getConf()));

    IdentifiedCertprofile profile = caManager.createCertprofile(newDbEntry);
    if (profile == null) {
      throw new CaMgmtException("could not create certprofile object");
    }

    boolean failed = true;
    try {
      changeIfNotNull("PROFILE", col(INT, "ID", nameId.getId()), col(STRING, "TYPE", type),
          col(STRING, "CONF", conf));
      failed = false;
      return profile;
    } finally {
      if (failed) {
        profile.shutdown();
      }
    }
  } // method changeCertprofile

  private static SqlColumn col(ColumnType type, String name, Object value) {
    return new SqlColumn(type, name, value);
  }

  private static SqlColumn col(ColumnType type, String name, Object value, boolean sensitive,
      boolean signerConf) {
    return new SqlColumn(type, name, value, sensitive, signerConf);
  }

  private static String str(String sa, String sb) {
    return (sa != null) ? getRealString(sa) : sb;
  }

  private void changeIfNotNull(String tableName, SqlColumn whereColumn, SqlColumn... columns)
      throws CaMgmtException {
    StringBuilder buf = new StringBuilder("UPDATE ");
    buf.append(tableName).append(" SET ");
    boolean noAction = true;
    for (SqlColumn col : columns) {
      if (col.getValue() != null) {
        noAction = false;
        buf.append(col.getName()).append("=?,");
      }
    }

    if (noAction) {
      throw new IllegalArgumentException("nothing to change");
    }

    buf.deleteCharAt(buf.length() - 1); // delete the last ','
    buf.append(" WHERE ").append(whereColumn.getName()).append("=?");

    String sql = buf.toString();

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      Map<String, String> changedColumns = new HashMap<>();

      int index = 1;
      for (SqlColumn col : columns) {
        if (col.getValue() != null) {
          setColumn(changedColumns, ps, index, col);
          index++;
        }
      }
      setColumn(null, ps, index, whereColumn);

      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not update table " + tableName);
      }

      LOG.info("updated table {} WHERE {}={}: {}", tableName,
          whereColumn.getName(), whereColumn.getValue(), changedColumns);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  }

  private void setColumn(Map<String, String> changedColumns, PreparedStatement ps,
      int index, SqlColumn column) throws SQLException {
    String name = column.getName();
    ColumnType type = column.getType();
    Object value = column.getValue();

    boolean sensitive = column.isSensitive();

    String valText;
    if (type == STRING) {
      String val = getRealString((String) value);
      ps.setString(index, val);

      valText = val;
      if (val != null && column.isSignerConf()) {
        valText = SignerConf.eraseSensitiveData(valText);

        if (valText.length() > 100) {
          valText = StringUtil.concat(valText.substring(0, 97), "...");
        }
      }
    } else if (type == ColumnType.INT) {
      if (value == null) {
        ps.setNull(index, Types.INTEGER);
        valText = "null";
      } else {
        int val = ((Integer) value).intValue();
        ps.setInt(index, val);
        valText = Integer.toString(val);
      }
    } else if (type == ColumnType.BOOL) {
      if (value == null) {
        ps.setNull(index, Types.INTEGER);
        valText = "null";
      } else {
        int val = (Boolean) value ? 1 : 0;
        ps.setInt(index, val);
        valText = Integer.toString(val);
      }
    } else {
      throw new RuntimeException("should not reach here, unknown type " + column.getType());
    }

    if (changedColumns != null) {
      changedColumns.put(name, sensitive ? "*****" : valText);
    }
  }

  RequestorEntryWrapper changeRequestor(NameId nameId, String type, String conf,
      PasswordResolver passwordResolver) throws CaMgmtException {
    ParamUtil.requireNonNull("nameId", nameId);
    RequestorEntryWrapper requestor = new RequestorEntryWrapper();

    if (RequestorEntry.TYPE_PBM.equalsIgnoreCase(type)) {
      if (!StringUtil.startsWithIgnoreCase(conf, "PBE:")) {
        try {
          conf = passwordResolver.protectPassword("PBE", conf.toCharArray());
        } catch (PasswordResolverException ex) {
          throw new CaMgmtException("could not encrypt requestor " + nameId.getName(), ex);
        }
      }
    }

    requestor.setDbEntry(new RequestorEntry(nameId, type, conf), passwordResolver);

    if (requestor.getDbEntry().isFaulty()) {
      throw new CaMgmtException("invalid requestor configuration");
    }

    changeIfNotNull("REQUESTOR", col(INT, "ID", nameId.getId()),
        col(STRING, "TYPE", type), col(STRING, "CONF", conf));
    return requestor;
  } // method changeRequestor

  SignerEntryWrapper changeSigner(String name, String type, String conf, String base64Cert,
      CaManagerImpl caManager, SecurityFactory securityFactory) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonNull("caManager", caManager);

    SignerEntry dbEntry = createSigner(name);
    String tmpType = (type == null ? dbEntry.getType() : type);
    if (conf != null) {
      conf = CaManagerImpl.canonicalizeSignerConf(tmpType, conf, null, securityFactory);
    }

    SignerEntry newDbEntry = new SignerEntry(name, tmpType,
        (conf == null ? dbEntry.getConf() : conf),
        (base64Cert == null ? dbEntry.getBase64Cert() : base64Cert));
    SignerEntryWrapper responder = caManager.createSigner(newDbEntry);

    changeIfNotNull("SIGNER", col(STRING, "NAME", name), col(STRING, "TYPE", type),
        col(STRING, "CERT", base64Cert), col(STRING, "CONF", conf, false, true));
    return responder;
  } // method changeSigner

  IdentifiedCertPublisher changePublisher(String name, String type, String conf,
      CaManagerImpl caManager) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonNull("caManager", caManager);

    PublisherEntry currentDbEntry = createPublisher(name);
    PublisherEntry dbEntry = new PublisherEntry(currentDbEntry.getIdent(),
        (type == null ? currentDbEntry.getType() : type),
        (conf == null ? currentDbEntry.getConf() : conf));
    IdentifiedCertPublisher publisher = caManager.createPublisher(dbEntry);

    changeIfNotNull("PUBLISHER", col(STRING, "NAME", name), col(STRING, "TYPE", type),
        col(STRING, "CONF", conf));
    return publisher;
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

    int caId = getNonNullIdForName(sqlSelectCaId, caName);
    int profileId = getNonNullIdForName(sqlSelectProfileId, profileName);
    final String sql = "DELETE FROM CA_HAS_PROFILE WHERE CA_ID=? AND PROFILE_ID=?";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setInt(1, caId);
      ps.setInt(2, profileId);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not remove profile " + profileName + " from CA " + caName);
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

    int caId = getNonNullIdForName(sqlSelectCaId, caName);
    int requestorId = getNonNullIdForName(sqlSelectRequestorId, requestorName);
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
    int caId = getNonNullIdForName(sqlSelectCaId, caName);
    int publisherId = getNonNullIdForName(sqlSelectPublisherId, publisherName);

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
    String sql = "UPDATE CA SET REV_INFO=? WHERE NAME=?";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, revocationInfo.getEncoded());
      ps.setString(2, caName);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not revoke CA " + caName);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method revokeCa

  void addSigner(SignerEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    final String sql = "INSERT INTO SIGNER (NAME,TYPE,CERT,CONF) VALUES (?,?,?,?)";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setString(idx++, dbEntry.getName());
      ps.setString(idx++, dbEntry.getType());
      ps.setString(idx++, dbEntry.getBase64Cert());
      ps.setString(idx++, dbEntry.getConf());
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add signer " + dbEntry.getName());
      }

      LOG.info("added signer: {}", dbEntry.toString(false, true));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addSigner

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

    final String sql = "UPDATE CA SET REV_INFO=? WHERE NAME=?";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setNull(1, Types.VARCHAR);
      ps.setString(2, caName);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not unrevoke CA " + caName);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method unrevokeCa

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
    Integer existingId = getIdForName(sqlSelectUserId, name);
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

  void changeUser(ChangeUserEntry userEntry) throws CaMgmtException {
    String username = userEntry.getIdent().getName();

    Integer existingId = getIdForName(sqlSelectUserId, username);
    if (existingId == null) {
      throw new CaMgmtException(concat("user '", username, " ' does not exist"));
    }
    userEntry.getIdent().setId(existingId);

    String password = userEntry.getPassword();
    String hashedPassword = null;
    if (password != null) {
      hashedPassword = PasswordHash.createHash(password);
    }

    changeIfNotNull("TUSER", col(INT, "ID", existingId), col(BOOL, "ACTIVE", userEntry.getActive()),
        col(STRING, "PASSWORD", hashedPassword, true, false));
  } // method changeUser

  void removeUserFromCa(String username, String caName) throws CaMgmtException {
    Integer id = getIdForName(sqlSelectUserId, username);
    if (id == null) {
      throw new CaMgmtException("unknown user " + username);
    }

    int caId = getNonNullIdForName(sqlSelectCaId, caName);

    final String sql = "DELETE FROM CA_HAS_USER WHERE CA_ID=? AND USER_ID=?";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setInt(1, caId);
      ps.setInt(2, id);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not remove user " + username + " from CA " + caName);
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
    Integer existingId = getIdForName(sqlSelectUserId, userIdent.getName());
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

      String profilesText = StringUtil.collectionAsString(user.getProfiles(), ",");
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
    Integer existingId = getIdForName(sqlSelectUserId, user);
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
        List<String> list = StringUtil.split(rs.getString("PROFILES"), ",");
        Set<String> profiles = (list == null) ? null : new HashSet<>(list);
        CaHasUserEntry caHasUser = new CaHasUserEntry(new NameId(existingId, user));
        caHasUser.setPermission(rs.getInt("PERMISSION"));
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
        List<String> list = StringUtil.split(rs.getString("PROFILES"), ",");
        Set<String> profiles = (list == null) ? null : new HashSet<>(list);
        CaHasUserEntry caHasUser = new CaHasUserEntry(new NameId(null, rs.getString("NAME")));
        caHasUser.setPermission(rs.getInt("PERMISSION"));
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

    final String sql = sqlSelectUser;
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

      ident.setId(rs.getInt("ID"));
      return new UserEntry(ident, rs.getBoolean("ACTIVE"), rs.getString("PASSWORD"));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method getUser

  private static void setBoolean(PreparedStatement ps, int index, boolean bo) throws SQLException {
    ps.setInt(index, bo ? 1 : 0);
  }

  private static String getRealString(String str) {
    return CaManager.NULL.equalsIgnoreCase(str) ? null : str;
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
