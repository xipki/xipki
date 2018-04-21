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
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.impl.SqlColumn.ColumnType;
import org.xipki.ca.server.impl.cmp.RequestorEntryWrapper;
import org.xipki.ca.server.impl.cmp.ResponderEntryWrapper;
import org.xipki.ca.server.impl.scep.ScepImpl;
import org.xipki.ca.server.impl.store.CertStore;
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
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.api.RequestorEntry;
import org.xipki.ca.server.mgmt.api.ResponderEntry;
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

  private static final ColumnType INT = ColumnType.INT;
  private static final ColumnType BOOL = ColumnType.BOOL;
  private static final ColumnType STRING = ColumnType.STRING;
  private static final ColumnType COLL_STRING = ColumnType.COLL_STRING;

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

  Map<String, String> createEnvParameters() throws CaMgmtException {
    Map<String, String> map = new HashMap<>();
    final String sql = "SELECT NAME,VALUE2 FROM ENVIRONMENT";
    Statement stmt = null;
    ResultSet rs = null;

    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        map.put(rs.getString("NAME"), rs.getString("VALUE2"));
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
    final String sql = sqls.sqlSelectProfile;
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

      return new PublisherEntry(new NameId(rs.getInt("ID"), name),
          rs.getString("TYPE"), rs.getString("CONF"));
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

      return new RequestorEntry(new NameId(rs.getInt("ID"), name), rs.getString("CERT"));
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

      return new X509CrlSignerEntry(name, rs.getString("SIGNER_TYPE"), rs.getString("SIGNER_CONF"),
          rs.getString("SIGNER_CERT"), rs.getString("CRL_CONTROL"));
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

      return new CmpControlEntry(name, rs.getString("CONF"));
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

      return new ResponderEntry(name, rs.getString("TYPE"), rs.getString("CONF"),
          rs.getString("CERT"));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource, sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createResponder

  X509CaInfo createCaInfo(String name, boolean masterMode, CertStore certstore)
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
        long revInvalidityTime = rs.getInt("RIT");
        Date revInvTime = (revInvalidityTime == 0) ? null : new Date(revInvalidityTime * 1000);
        revocationInfo = new CertRevocationInfo(rs.getInt("RR"), new Date(rs.getInt("RT") * 1000),
            revInvTime);
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
      X509CaEntry entry = new X509CaEntry(new NameId(rs.getInt("ID"), name), rs.getInt("SN_SIZE"),
          rs.getLong("NEXT_CRLNO"), rs.getString("SIGNER_TYPE"), rs.getString("SIGNER_CONF"),
          caUris, rs.getInt("NUM_CRLS"), rs.getInt("EXPIRATION_PERIOD"));
      entry.setCert(generateCert(rs.getString("CERT")));

      entry.setStatus(CaStatus.forName(rs.getString("STATUS")));
      entry.setMaxValidity(CertValidity.getInstance(rs.getString("MAX_VALIDITY")));
      entry.setKeepExpiredCertInDays(rs.getInt("KEEP_EXPIRED_CERT_DAYS"));

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

      entry.setDuplicateKeyPermitted((rs.getInt("DUPLICATE_KEY") != 0));
      entry.setDuplicateSubjectPermitted((rs.getInt("DUPLICATE_SUBJECT") != 0));
      entry.setSaveRequest((rs.getInt("SAVE_REQ") != 0));
      entry.setPermission(rs.getInt("PERMISSION"));
      entry.setRevocationInfo(revocationInfo);
      String validityModeS = rs.getString("VALIDITY_MODE");
      entry.setValidityMode(validityModeS == null
          ? ValidityMode.STRICT : ValidityMode.forName(validityModeS));

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

        List<String> list = StringUtil.splitByComma(rs.getString("PROFILES"));
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
      ps.setString(idx++, StringUtil.isBlank(encodedExtraCtrl) ? null : encodedExtraCtrl);
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

    final String sql = "INSERT INTO REQUESTOR (ID,NAME,CERT) VALUES (?,?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setInt(1, dbEntry.getIdent().getId());
      ps.setString(2, dbEntry.getIdent().getName());
      ps.setString(3, Base64.encodeToString(dbEntry.getCert().getEncoded()));
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

      setBoolean(ps, idx++, requestor.isRa());
      ps.setInt(idx++, requestor.getPermission());
      String profilesText = StringUtil.collectionAsStringByComma(requestor.getProfiles());
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

  void addCrlSigner(X509CrlSignerEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    String crlControl = dbEntry.getCrlControl();
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
        throw new CaMgmtException("Cannot change certificate of CA which has issued certificates");
      }
    }

    String signerType = entry.getSignerType();
    String signerConf = entry.getSignerConf();

    if (signerType != null || signerConf != null || cert != null) {
      // validate the signer configuration
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

        String tmpSignerType = (signerType == null ? rs.getString("SIGNER_TYPE") : signerType);

        String tmpSignerConf;
        if (signerConf == null) {
          tmpSignerConf = rs.getString("SIGNER_CONF");
        } else {
          signerConf = CaManagerImpl.canonicalizeSignerConf(
              tmpSignerType, signerConf, null, securityFactory);
          tmpSignerConf = signerConf;
        }

        // need the certificate to validity the signer
        X509Certificate tmpCert;
        if (cert != null) {
          tmpCert = cert;
        } else {
          try {
            tmpCert = X509Util.parseBase64EncodedCert(rs.getString("CERT"));
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

    String status = (entry.getStatus() == null) ? null : entry.getStatus().name();
    String maxValidity = (entry.getMaxValidity() == null) ? null
        : entry.getMaxValidity().toString();
    String extraControl = (entry.getExtraControl() == null) ? null
        : entry.getExtraControl().getEncoded();
    String validityMode = (entry.getValidityMode() == null) ? null
        : entry.getValidityMode().name();

    changeIfNotNull("CA", col(INT, "ID", entry.getIdent().getId()),
        col(INT, "SN_SIZE", entry.getSerialNoBitLen()), col(STRING, "STATUS", status),
        col(STRING, "SUBJECT", subject), col(STRING, "CERT", base64Cert),
        col(COLL_STRING, "CRL_URIS", entry.getCrlUris()),
        col(COLL_STRING, "DELTACRL_URIS", entry.getDeltaCrlUris()),
        col(COLL_STRING, "OCSP_URIS", entry.getOcspUris()),
        col(COLL_STRING, "CACERT_URIS", entry.getCaCertUris()),
        col(STRING, "MAX_VALIDITY", maxValidity), col(COLL_STRING, "SIGNER_TYPE", signerType),
        col(STRING, "CRLSIGNER_NAME", entry.getCrlSignerName()),
        col(STRING, "RESPONDER_NAME", entry.getResponderName()),
        col(STRING, "CMPCONTROL_NAME", entry.getCmpControlName()),
        col(BOOL, "DUPLICATE_KEY", entry.getDuplicateKeyPermitted()),
        col(BOOL, "DUPLICATE_SUBJECT", entry.getDuplicateSubjectPermitted()),
        col(BOOL, "SAVE_REQ", entry.getSaveRequest()),
        col(INT, "PERMISSION", entry.getPermission()),
        col(INT, "NUM_CRLS", entry.getNumCrls()),
        col(INT, "EXPIRATION_PERIOD", entry.getExpirationPeriod()),
        col(INT, "KEEP_EXPIRED_CERT_DAYS", entry.getKeepExpiredCertInDays()),
        col(STRING, "VALIDITY_MODE", validityMode),
        col(STRING, "EXTRA_CONTROL", extraControl),
        col(STRING, "SIGNER_CONF", signerConf, false, true));
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

  IdentifiedX509Certprofile changeCertprofile(NameId nameId, String type, String conf,
      CaManagerImpl caManager) throws CaMgmtException {
    CertprofileEntry currentDbEntry = createCertprofile(nameId.getName());
    CertprofileEntry newDbEntry = new CertprofileEntry(currentDbEntry.getIdent(),
        str(type, currentDbEntry.getType()), str(conf, currentDbEntry.getConf()));

    IdentifiedX509Certprofile profile = caManager.createCertprofile(newDbEntry);
    if (profile == null) {
      throw new CaMgmtException("could not create CertProfile object");
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

  CmpControl changeCmpControl(String name, String conf) throws CaMgmtException {
    CmpControl cmpControl;
    try {
      cmpControl = new CmpControl(new CmpControlEntry(name, conf));
    } catch (InvalidConfException ex) {
      throw new CaMgmtException(ex);
    }

    changeIfNotNull("CMPCONTROL", col(STRING, "NAME", name), col(STRING, "CONF", conf));
    return cmpControl;
  } // method changeCmpControl

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
        valText = SignerConf.toString(val, false, true);
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
    } else if (type == ColumnType.COLL_STRING) {
      @SuppressWarnings("unchecked")
      String val = StringUtil.collectionAsStringByComma((Collection<String>) value);
      ps.setString(index, val);
      valText = val;
    } else {
      throw new RuntimeException("should not reach here, unknown type " + column.getType());
    }

    if (changedColumns != null) {
      changedColumns.put(name, sensitive ? "*****" : valText);
    }
  }

  RequestorEntryWrapper changeRequestor(NameId nameId, String base64Cert)
      throws CaMgmtException {
    ParamUtil.requireNonNull("nameId", nameId);
    RequestorEntryWrapper requestor = new RequestorEntryWrapper();
    requestor.setDbEntry(new RequestorEntry(nameId, base64Cert));

    changeIfNotNull("REQUESTOR", col(INT, "ID", nameId.getId()), col(STRING, "CERT", base64Cert));
    return requestor;
  } // method changeRequestor

  ResponderEntryWrapper changeResponder(String name, String type, String conf,
      String base64Cert, CaManagerImpl caManager, SecurityFactory securityFactory)
      throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonNull("caManager", caManager);

    ResponderEntry dbEntry = createResponder(name);
    String tmpType = (type == null ? dbEntry.getType() : type);
    if (conf != null) {
      conf = CaManagerImpl.canonicalizeSignerConf(tmpType, conf, null, securityFactory);
    }

    ResponderEntry newDbEntry = new ResponderEntry(name, tmpType,
        (conf == null ? dbEntry.getConf() : conf),
        (base64Cert == null ? dbEntry.getBase64Cert() : base64Cert));
    ResponderEntryWrapper responder = caManager.createResponder(newDbEntry);

    changeIfNotNull("RESPONDER", col(STRING, "NAME", name), col(STRING, "TYPE", type),
        col(STRING, "CERT", base64Cert), col(STRING, "CONF", conf, false, true));
    return responder;
  } // method changeResponder

  X509CrlSignerEntryWrapper changeCrlSigner(String name, String signerType, String signerConf,
      String base64Cert, String crlControl, CaManagerImpl caManager,
      SecurityFactory securityFactory) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonNull("caManager", caManager);

    X509CrlSignerEntry dbEntry = createCrlSigner(name);
    if (crlControl != null) { // validate crlControl
      try {
        new CrlControl(crlControl);
      } catch (InvalidConfException ex) {
        throw new CaMgmtException(concat("invalid CRL control '", crlControl, "'"));
      }
    }

    String tmpSignerType = (signerType == null) ? dbEntry.getType() : signerType;
    try {
      if ("ca".equalsIgnoreCase(tmpSignerType)) {
        dbEntry = new X509CrlSignerEntry(name, "ca", null, null,
            (crlControl == null ? dbEntry.getCrlControl() : crlControl));
      } else {
        if (signerConf != null) {
          signerConf = CaManagerImpl.canonicalizeSignerConf(tmpSignerType,
              signerConf, null, securityFactory);
        }

        dbEntry = new X509CrlSignerEntry(name, "ca",
            (signerConf == null ? dbEntry.getConf() : signerConf),
            (base64Cert == null ? dbEntry.getBase64Cert() : base64Cert),
            (crlControl == null ? dbEntry.getCrlControl() : crlControl));
      }
    } catch (InvalidConfException ex) {
      throw new CaMgmtException(ex);
    }

    X509CrlSignerEntryWrapper crlSigner = caManager.createX509CrlSigner(dbEntry);

    changeIfNotNull("CRLSIGNER", col(STRING, "NAME", name), col(STRING, "SIGNER_TYPE", signerType),
        col(STRING, "SIGNER_CERT", base64Cert), col(STRING, "CRL_CONTROL", crlControl),
        col(STRING, "SIGNER_CONF", signerConf, false, true));
    return crlSigner;
  } // method changeCrlSigner

  ScepImpl changeScep(String name, NameId caIdent, Boolean active, String responderName,
      Set<String> certProfiles, String control, CaManagerImpl caManager,
      final SecurityFactory securityFactory) throws CaMgmtException {
    ScepImpl scep;
    try {
      ScepEntry dbEntry = getScep(name, caManager.idNameMap());
      ScepEntry newDbEntry = new ScepEntry(name, dbEntry.getCaIdent(),
          (active == null ? dbEntry.isActive() : active),
          (responderName ==  null ? dbEntry.getResponderName() : responderName),
          (certProfiles == null ? dbEntry.getCertProfiles() : certProfiles),
          (control == null ? dbEntry.getControl() : getRealString(control)));
      scep = new ScepImpl(newDbEntry, caManager);
    } catch (InvalidConfException ex) {
      throw new CaMgmtException(ex);
    }

    changeIfNotNull("SCEP", col(STRING, "NAME", name), col(INT, "CA_ID", caIdent.getId()),
        col(BOOL, "ACTIVE", active), col(STRING, "RESPONDER_NAME", responderName),
        col(COLL_STRING, "PROFILES", certProfiles), col(STRING, "CONTROL", control));
    return scep;
  } // method changeScep

  void changeEnvParam(String name, String value) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonNull("value", value);

    if (CaManagerImpl.ENV_EPOCH.equalsIgnoreCase(name)) {
      throw new CaMgmtException(concat("environment ", name, " is reserved"));
    }

    changeIfNotNull("ENVIRONMENT", col(STRING, "NAME", name), col(STRING, "VALUE2", value));
  } // method changeEnvParam

  IdentifiedX509CertPublisher changePublisher(String name, String type,
      String conf, CaManagerImpl caManager) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonNull("caManager", caManager);

    PublisherEntry currentDbEntry = createPublisher(name);
    PublisherEntry dbEntry = new PublisherEntry(currentDbEntry.getIdent(),
        (type == null ? currentDbEntry.getType() : type),
        (conf == null ? currentDbEntry.getConf() : conf));
    IdentifiedX509CertPublisher publisher = caManager.createPublisher(dbEntry);

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

      Set<String> profiles = StringUtil.splitByCommaAsSet(rs.getString("PROFILES"));

      return new ScepEntry(name, idNameMap.getCa(rs.getInt("CA_ID")), rs.getBoolean("ACTIVE"),
          rs.getString("RESPONDER_NAME"), profiles, rs.getString("CONTROL"));
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

  void changeUser(ChangeUserEntry userEntry) throws CaMgmtException {
    String username = userEntry.getIdent().getName();

    Integer existingId = getIdForName(sqls.sqlSelectUserId, username);
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
        List<String> list = StringUtil.splitByComma(rs.getString("PROFILES"));
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
        List<String> list = StringUtil.splitByComma(rs.getString("PROFILES"));
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
