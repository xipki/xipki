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

package org.xipki.ca.server;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;

import java.io.IOException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CmpControl;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.CtlogControl;
import org.xipki.ca.api.mgmt.MgmtEntry;
import org.xipki.ca.api.mgmt.ProtocolSupport;
import org.xipki.ca.api.mgmt.RevokeSuspendedControl;
import org.xipki.ca.api.mgmt.ScepControl;
import org.xipki.ca.api.mgmt.ValidityMode;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.StringUtil;
import org.xipki.util.Validity;

/**
 * Execute the database queries to manage CA system.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
class CaManagerQueryExecutor {

  private static enum ColumnType {
    INT,
    STRING,
    BOOL
  } // class ColumnType

  private static enum Table {
    // SMALLINT or INT
    REQUESTOR,
    PUBLISHER,
    PROFILE,
    TUSER,
    CA,
    // BigInt
    CA_HAS_USER;
  }

  private static class SqlColumn {

    private ColumnType type;
    private String name;
    private Object value;
    private boolean sensitive;
    private boolean signerConf;

    public SqlColumn(ColumnType type, String name, Object value) {
      this(type, name, value, false, false);
    }

    public SqlColumn(ColumnType type, String name, Object value, boolean sensitive,
        boolean signerConf) {
      this.type = notNull(type, "type");
      this.name = notNull(name, "name");
      this.value = value;
      this.sensitive = sensitive;
      this.signerConf = signerConf;
    }

    public ColumnType getType() {
      return type;
    }

    public String getName() {
      return name;
    }

    public Object getValue() {
      return value;
    }

    public boolean isSensitive() {
      return sensitive;
    }

    public boolean isSignerConf() {
      return signerConf;
    }

  } // class SqlColumn

  static class SystemEvent {

    private final String name;

    private final String owner;

    private final long eventTime;

    SystemEvent(String name, String owner, long eventTime) {
      this.name = notBlank(name, "name");
      this.owner = notBlank(owner, "owner");
      this.eventTime = eventTime;
    }

    public String getName() {
      return name;
    }

    public String getOwner() {
      return owner;
    }

    public long getEventTime() {
      return eventTime;
    }

  } // class SystemEvent

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

  private final Map<Table, AtomicLong> cachedIdMap = new HashMap<>();

  CaManagerQueryExecutor(DataSourceWrapper datasource) {
    for (Table m : Table.values()) {
      cachedIdMap.put(m, new AtomicLong(0));
    }

    this.datasource = notNull(datasource, "datasource");
    this.sqlSelectProfileId = buildSelectFirstSql("ID FROM PROFILE WHERE NAME=?");
    this.sqlSelectProfile = buildSelectFirstSql("ID,TYPE,CONF FROM PROFILE WHERE NAME=?");
    this.sqlSelectPublisherId = buildSelectFirstSql("ID FROM PUBLISHER WHERE NAME=?");
    this.sqlSelectPublisher = buildSelectFirstSql("ID,TYPE,CONF FROM PUBLISHER WHERE NAME=?");
    this.sqlSelectRequestorId = buildSelectFirstSql("ID FROM REQUESTOR WHERE NAME=?");
    this.sqlSelectRequestor = buildSelectFirstSql("ID,TYPE,CONF FROM REQUESTOR WHERE NAME=?");
    this.sqlSelectSigner = buildSelectFirstSql("TYPE,CERT,CONF FROM SIGNER WHERE NAME=?");
    this.sqlSelectCaId = buildSelectFirstSql("ID FROM CA WHERE NAME=?");
    this.sqlSelectCa = buildSelectFirstSql("ID,SN_SIZE,NEXT_CRLNO,STATUS,MAX_VALIDITY,CERT,"
        + "CERTCHAIN,SIGNER_TYPE,CMP_RESPONDER_NAME,SCEP_RESPONDER_NAME,CRL_SIGNER_NAME,"
        + "CMP_CONTROL,CRL_CONTROL,SCEP_CONTROL,CTLOG_CONTROL,"
        + "PROTOCOL_SUPPORT,SAVE_REQ,PERMISSION,NUM_CRLS,KEEP_EXPIRED_CERT_DAYS,"
        + "EXPIRATION_PERIOD,REV_INFO,VALIDITY_MODE,CA_URIS,EXTRA_CONTROL,SIGNER_CONF,"
        + "DHPOC_CONTROL,REVOKE_SUSPENDED_CONTROL "
        + "FROM CA WHERE NAME=?");
    this.sqlNextSelectCrlNo = buildSelectFirstSql("NEXT_CRLNO FROM CA WHERE ID=?");
    this.sqlSelectSystemEvent = buildSelectFirstSql(
        "EVENT_TIME,EVENT_OWNER FROM SYSTEM_EVENT WHERE NAME=?");
    this.sqlSelectUserId = buildSelectFirstSql("ID FROM TUSER WHERE NAME=?");
    this.sqlSelectUser = buildSelectFirstSql("ID,ACTIVE,PASSWORD FROM TUSER WHERE NAME=?");
  } // constructor

  private String buildSelectFirstSql(String coreSql) {
    return datasource.buildSelectFirstSql(1, coreSql);
  }

  private X509Cert generateCert(String b64Cert)
      throws CaMgmtException {
    if (b64Cert == null) {
      return null;
    }

    return parseCert(Base64.decode(b64Cert));
  } // method generateCert

  private List<X509Cert> generateCertchain(String encodedCertchain)
      throws CaMgmtException {
    if (StringUtil.isBlank(encodedCertchain)) {
      return null;
    }

    try {
      List<X509Cert> certs = X509Util.listCertificates(encodedCertchain);
      return CollectionUtil.isEmpty(certs) ? null : certs;
    } catch (CertificateException | IOException ex) {
      throw new CaMgmtException(ex);
    }
  } // method generateCertchain

  private Statement createStatement()
      throws CaMgmtException {
    try {
      return datasource.createStatement();
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }
  } // method createStatement

  private PreparedStatement prepareStatement(String sql)
      throws CaMgmtException {
    try {
      return datasource.prepareStatement(sql);
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
  SystemEvent getSystemEvent(String eventName)
      throws CaMgmtException {
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method getSystemEvent

  private void deleteSystemEvent(String eventName)
      throws CaMgmtException {
    final String sql = "DELETE FROM SYSTEM_EVENT WHERE NAME=?";
    PreparedStatement ps = null;

    try {
      ps = prepareStatement(sql);
      ps.setString(1, eventName);
      ps.executeUpdate();
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method deleteSystemEvent

  private void addSystemEvent(SystemEvent systemEvent)
      throws CaMgmtException {
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addSystemEvent

  void changeSystemEvent(SystemEvent systemEvent)
      throws CaMgmtException {
    deleteSystemEvent(systemEvent.getName());
    addSystemEvent(systemEvent);
  } // method changeSystemEvent

  Map<String, Integer> createCaAliases()
      throws CaMgmtException {
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, rs);
    }

    return map;
  } // method createCaAliases

  MgmtEntry.Certprofile createCertprofile(String name)
      throws CaMgmtException {
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

      return new MgmtEntry.Certprofile(new NameId(rs.getInt("ID"), name),
          rs.getString("TYPE"), rs.getString("CONF"));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createCertprofile

  List<String> namesFromTable(String table)
      throws CaMgmtException {
    final String sql = concat("SELECT NAME FROM ", table);
    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      List<String> names = new LinkedList<>();
      while (rs.next()) {
        String name = rs.getString("NAME");
        if (StringUtil.isNotBlank(name)) {
          names.add(name);
        }
      }

      return names;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method namesFromTable

  MgmtEntry.Publisher createPublisher(String name)
      throws CaMgmtException {
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

      return new MgmtEntry.Publisher(new NameId(rs.getInt("ID"), name),
          rs.getString("TYPE"), rs.getString("CONF"));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createPublisher

  Integer getRequestorId(String requestorName)
      throws CaMgmtException {
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method getRequestorId

  MgmtEntry.Requestor createRequestor(String name)
      throws CaMgmtException {
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

      return new MgmtEntry.Requestor(new NameId(rs.getInt("ID"), name),
          rs.getString("TYPE"), rs.getString("CONF"));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createRequestor

  MgmtEntry.Signer createSigner(String name)
      throws CaMgmtException {
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

      return new MgmtEntry.Signer(name, rs.getString("TYPE"), rs.getString("CONF"),
          rs.getString("CERT"));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createSigner

  CaInfo createCaInfo(String name, boolean masterMode, CertStore certstore)
      throws CaMgmtException {
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
      int snSize = rs.getInt("SN_SIZE");
      if (snSize > CaManager.MAX_SERIALNUMBER_SIZE) {
        snSize = CaManager.MAX_SERIALNUMBER_SIZE;
      } else if (snSize < CaManager.MIN_SERIALNUMBER_SIZE) {
        snSize = CaManager.MIN_SERIALNUMBER_SIZE;
      }

      MgmtEntry.Ca entry = new MgmtEntry.Ca(new NameId(rs.getInt("ID"), name), snSize,
          rs.getLong("NEXT_CRLNO"), rs.getString("SIGNER_TYPE"), rs.getString("SIGNER_CONF"),
          caUris, rs.getInt("NUM_CRLS"), rs.getInt("EXPIRATION_PERIOD"));
      entry.setCert(generateCert(rs.getString("CERT")));
      entry.setDhpocControl(rs.getString("DHPOC_CONTROL"));
      String str = rs.getString("REVOKE_SUSPENDED_CONTROL");
      RevokeSuspendedControl revokeSuspended = str == null
          ? new RevokeSuspendedControl(false) : new RevokeSuspendedControl(str);
      entry.setRevokeSuspendedControl(revokeSuspended);

      List<X509Cert> certchain = generateCertchain(rs.getString("CERTCHAIN"));
      // validate certchain
      if (CollectionUtil.isNotEmpty(certchain)) {
        buildCertChain(entry.getCert(), certchain);
        entry.setCertchain(certchain);
      }

      entry.setStatus(CaStatus.forName(rs.getString("STATUS")));
      entry.setMaxValidity(Validity.getInstance(rs.getString("MAX_VALIDITY")));
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

      String ctlogControl = rs.getString("CTLOG_CONTROL");
      if (StringUtil.isNotBlank(ctlogControl)) {
        try {
          entry.setCtlogControl(new CtlogControl(ctlogControl));
        } catch (InvalidConfException ex) {
          throw new CaMgmtException("invalid CTLOG_CONTROL: " + scepcontrol, ex);
        }
      }

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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createCaInfo

  Set<MgmtEntry.CaHasRequestor> createCaHasRequestors(NameId ca)
      throws CaMgmtException {
    Map<Integer, String> idNameMap = getIdNameMap("REQUESTOR");

    final String sql =
        "SELECT REQUESTOR_ID,RA,PERMISSION,PROFILES FROM CA_HAS_REQUESTOR WHERE CA_ID=?";
    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      stmt.setInt(1, ca.getId());
      rs = stmt.executeQuery();

      Set<MgmtEntry.CaHasRequestor> ret = new HashSet<>();
      while (rs.next()) {
        int id = rs.getInt("REQUESTOR_ID");
        String name = idNameMap.get(id);

        List<String> list = StringUtil.split(rs.getString("PROFILES"), ",");
        Set<String> profiles = (list == null) ? null : new HashSet<>(list);
        MgmtEntry.CaHasRequestor entry = new MgmtEntry.CaHasRequestor(new NameId(id, name));
        entry.setRa(rs.getBoolean("RA"));
        entry.setPermission(rs.getInt("PERMISSION"));
        entry.setProfiles(profiles);

        ret.add(entry);
      }

      return ret;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createCaHasRequestors

  Set<Integer> createCaHasProfiles(NameId ca)
      throws CaMgmtException {
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createCaHasProfiles

  Set<Integer> createCaHasPublishers(NameId ca)
      throws CaMgmtException {
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method createCaHasPublishers

  boolean deleteRowWithName(String name, String table)
      throws CaMgmtException {
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method deleteRowWithName

  void addCa(MgmtEntry.Ca caEntry)
      throws CaMgmtException {
    notNull(caEntry, "caEntry");

    caEntry.getIdent().setId((int) getNextId(Table.CA));

    final String sql = "INSERT INTO CA (ID,NAME,SUBJECT,SN_SIZE,NEXT_CRLNO,STATUS,CA_URIS,"//7
        + "MAX_VALIDITY,CERT,CERTCHAIN,SIGNER_TYPE,CRL_SIGNER_NAME,"//5
        + "CMP_RESPONDER_NAME,SCEP_RESPONDER_NAME,CRL_CONTROL,CMP_CONTROL,SCEP_CONTROL,"//5
        + "CTLOG_CONTROL,PROTOCOL_SUPPORT,SAVE_REQ,PERMISSION,"//6
        + "NUM_CRLS,EXPIRATION_PERIOD,KEEP_EXPIRED_CERT_DAYS,VALIDITY_MODE,EXTRA_CONTROL,"//5
        + "SIGNER_CONF,DHPOC_CONTROL,REVOKE_SUSPENDED_CONTROL) "
        + "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    // insert to table ca
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      int idx = 1;
      ps.setInt(idx++, caEntry.getIdent().getId());
      ps.setString(idx++, caEntry.getIdent().getName());
      ps.setString(idx++, caEntry.getSubject());
      ps.setInt(idx++, caEntry.getSerialNoLen());
      ps.setLong(idx++, caEntry.getNextCrlNumber());
      ps.setString(idx++, caEntry.getStatus().getStatus());

      CaUris caUris = caEntry.getCaUris();
      ps.setString(idx++, (caUris == null) ? null : caEntry.getCaUris().getEncoded());
      ps.setString(idx++, caEntry.getMaxValidity().toString());
      byte[] encodedCert = caEntry.getCert().getEncoded();
      ps.setString(idx++, Base64.encodeToString(encodedCert));

      List<X509Cert> certchain = caEntry.getCertchain();
      if (CollectionUtil.isEmpty(certchain)) {
        ps.setString(idx++, null);
      } else {
        certchain = buildCertChain(caEntry.getCert(), certchain);
        ps.setString(idx++, encodeCertchain(certchain));
      }

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

      CtlogControl ctlogControl = caEntry.getCtlogControl();
      ps.setString(idx++, (ctlogControl == null ? null : ctlogControl.getConf()));

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
      ps.setString(idx++, caEntry.getDhpocControl());
      RevokeSuspendedControl revokeSuspended = caEntry.getRevokeSuspendedControl();
      ps.setString(idx++, revokeSuspended == null ? null : revokeSuspended.getConf());

      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not add CA " + caEntry.getIdent());
      }
      if (LOG.isInfoEnabled()) {
        LOG.info("add CA '{}': {}", caEntry.getIdent(), caEntry.toString(false, true));
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addCa

  void addCaAlias(String aliasName, NameId ca)
      throws CaMgmtException {
    notNull(aliasName, "aliasName");
    notNull(ca, "ca");

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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addCaAlias

  void addCertprofile(MgmtEntry.Certprofile dbEntry)
      throws CaMgmtException {
    notNull(dbEntry, "dbEntry");
    final String sql = "INSERT INTO PROFILE (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";

    dbEntry.getIdent().setId((int) getNextId(Table.PROFILE));

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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addCertprofile

  void addCertprofileToCa(NameId profile, NameId ca)
      throws CaMgmtException {
    notNull(profile, "profile");
    notNull(ca, "ca");

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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addCertprofileToCa

  void addRequestor(MgmtEntry.Requestor dbEntry)
      throws CaMgmtException {
    notNull(dbEntry, "dbEntry");

    dbEntry.getIdent().setId((int) getNextId(Table.REQUESTOR));

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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addRequestor

  void addEmbeddedRequestor(String requestorName)
      throws CaMgmtException {
    requestorName = requestorName.toLowerCase();
    String sql = sqlSelectRequestorId;
    ResultSet rs = null;
    PreparedStatement stmt = null;

    int nextId = (int) getNextId(Table.REQUESTOR);

    try {
      sql = "INSERT INTO REQUESTOR (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";
      stmt = prepareStatement(sql);

      stmt.setInt(1, nextId);
      stmt.setString(2, requestorName);
      // ANY VALUE
      stmt.setString(3, "EMBEDDED");
      // ANY VALUE
      stmt.setString(4, "DEFAULT");
      stmt.executeUpdate();
      LOG.info("added requestor '{}'", requestorName);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // method addRequestorIfNeeded

  void addRequestorToCa(MgmtEntry.CaHasRequestor requestor, NameId ca)
      throws CaMgmtException {
    notNull(requestor, "requestor");
    notNull(ca, "ca");

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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addRequestorToCa

  void addPublisher(MgmtEntry.Publisher dbEntry)
      throws CaMgmtException {
    notNull(dbEntry, "dbEntry");
    final String sql = "INSERT INTO PUBLISHER (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";

    dbEntry.getIdent().setId((int) getNextId(Table.PUBLISHER));

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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addPublisher

  void addPublisherToCa(NameId publisher, NameId ca)
      throws CaMgmtException {
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addPublisherToCa

  void changeCa(MgmtEntry.ChangeCa changeCaEntry, MgmtEntry.Ca currentCaEntry,
      SecurityFactory securityFactory)
          throws CaMgmtException {
    notNull(changeCaEntry, "changeCaEntry");
    notNull(securityFactory, "securityFactory");

    byte[] encodedCert = changeCaEntry.getEncodedCert();
    if (encodedCert != null) {
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

    X509Cert caCert = null;

    if (signerType != null || signerConf != null || encodedCert != null
        || CollectionUtil.isNotEmpty(changeCaEntry.getEncodedCertchain())) {
      // need CA certificate
      if (encodedCert != null) {
        caCert = parseCert(encodedCert);
      } else {
        final String sql = "SELECT CERT FROM CA WHERE ID=?";

        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
          stmt = prepareStatement(sql);
          stmt.setInt(1, changeCaEntry.getIdent().getId());
          rs = stmt.executeQuery();
          if (!rs.next()) {
            throw new CaMgmtException("unknown CA '" + changeCaEntry.getIdent());
          }

          caCert = parseCert(Base64.decode(rs.getString("CERT")));
        } catch (SQLException ex) {
          throw new CaMgmtException(datasource.translate(sql, ex));
        } finally {
          datasource.releaseResources(stmt, rs);
        }
      }

      if (signerType != null || signerConf != null || encodedCert != null) {
        // validate the signer configuration
        final String sql = "SELECT SIGNER_TYPE,SIGNER_CONF FROM CA WHERE ID=?";
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

          try {
            List<String[]> signerConfs = MgmtEntry.Ca.splitCaSignerConfs(signerConf);
            for (String[] m : signerConfs) {
              securityFactory.createSigner(signerType, new SignerConf(m[1]), caCert);
            }
          } catch (XiSecurityException | ObjectCreationException ex) {
            throw new CaMgmtException("could not create signer for CA '"
                + changeCaEntry.getIdent() + "'" + ex.getMessage(), ex);
          }
        } catch (SQLException ex) {
          throw new CaMgmtException(datasource.translate(sql, ex));
        } finally {
          datasource.releaseResources(stmt, rs);
        }
      }
    } // end if (signerType)

    String subject = null;
    String base64Cert = null;
    if (encodedCert != null) {
      try {
        subject = X509Util.parseCert(encodedCert).getIssuerRfc4519Text();
        base64Cert = Base64.encodeToString(encodedCert);
      } catch (CertificateException ex) {
        throw new CaMgmtException("could not parse the certificate", ex);
      }
    }

    // CHECKSTYLE:SKIP
    String status = (changeCaEntry.getStatus() == null) ? null : changeCaEntry.getStatus().name();
    // CHECKSTYLE:SKIP
    String maxValidity = (changeCaEntry.getMaxValidity() == null) ? null
        : changeCaEntry.getMaxValidity().toString();
    // CHECKSTYLE:SKIP
    String extraControl = (changeCaEntry.getExtraControl() == null) ? null
        : changeCaEntry.getExtraControl().getEncoded();
    // CHECKSTYLE:SKIP
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
      ProtocolSupport support = new ProtocolSupport(oldSupport.isCmp(),
          oldSupport.isRest(), oldSupport.isScep());

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

    String certchainStr = null;
    if (changeCaEntry.getEncodedCertchain() != null) {
      List<byte[]> encodedCertchain = changeCaEntry.getEncodedCertchain();
      if (encodedCertchain.size() == 0) {
        certchainStr = CaManager.NULL;
      } else {
        List<X509Cert> certs = new LinkedList<>();
        for (byte[] m : changeCaEntry.getEncodedCertchain()) {
          certs.add(parseCert(m));
        }

        certs = buildCertChain(caCert, certs);
        certchainStr = encodeCertchain(certs);
      }
    }

    changeIfNotNull("CA", col(INT, "ID", changeCaEntry.getIdent().getId()),
        col(INT, "SN_SIZE", changeCaEntry.getSerialNoLen()), col(STRING, "STATUS", status),
        col(STRING, "SUBJECT", subject), col(STRING, "CERT", base64Cert),
        col(STRING, "CERTCHAIN", certchainStr),
        col(STRING, "CA_URIS", caUrisStr),
        col(STRING, "MAX_VALIDITY", maxValidity), col(STRING, "SIGNER_TYPE", signerType),
        col(STRING, "CRL_SIGNER_NAME", changeCaEntry.getCrlSignerName()),
        col(STRING, "CMP_RESPONDER_NAME", changeCaEntry.getCmpResponderName()),
        col(STRING, "SCEP_RESPONDER_NAME", changeCaEntry.getScepResponderName()),
        col(STRING, "CMP_CONTROL", changeCaEntry.getCmpControl()),
        col(STRING, "CRL_CONTROL", changeCaEntry.getCrlControl()),
        col(STRING, "SCEP_CONTROL", changeCaEntry.getScepControl()),
        col(STRING, "CTLOG_CONTROL", changeCaEntry.getCtlogControl()),
        col(STRING, "PROTOCOL_SUPPORT", protocolSupportStr),
        col(BOOL, "SAVE_REQ", changeCaEntry.getSaveRequest()),
        col(INT, "PERMISSION", changeCaEntry.getPermission()),
        col(INT, "NUM_CRLS", changeCaEntry.getNumCrls()),
        col(INT, "EXPIRATION_PERIOD", changeCaEntry.getExpirationPeriod()),
        col(INT, "KEEP_EXPIRED_CERT_DAYS", changeCaEntry.getKeepExpiredCertInDays()),
        col(STRING, "VALIDITY_MODE", validityMode),
        col(STRING, "EXTRA_CONTROL", extraControl),
        col(STRING, "SIGNER_CONF", signerConf, false, true),
        col(STRING, "DHPOC_CONTROL", changeCaEntry.getDhpocControl(), false, true),
        col(STRING, "REVOKE_SUSPENDED_CONTROL", changeCaEntry.getRevokeSuspendedControl()));
  } // method changeCa

  void commitNextCrlNoIfLess(NameId ca, long nextCrlNo)
      throws CaMgmtException {
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
        throw new CaMgmtException(datasource.translate(sql, ex));
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
          throw new CaMgmtException(datasource.translate(sql, ex));
        }
      }
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method commitNextCrlNoIfLess

  IdentifiedCertprofile changeCertprofile(NameId nameId, String type, String conf,
      CaManagerImpl caManager)
          throws CaMgmtException {
    MgmtEntry.Certprofile currentDbEntry = createCertprofile(nameId.getName());
    MgmtEntry.Certprofile newDbEntry = new MgmtEntry.Certprofile(currentDbEntry.getIdent(),
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
        profile.close();
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method changeIfNotNull

  private void setColumn(Map<String, String> changedColumns, PreparedStatement ps,
      int index, SqlColumn column)
          throws SQLException {
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
      throw new IllegalStateException("should not reach here, unknown type " + column.getType());
    }

    if (changedColumns != null) {
      changedColumns.put(name, sensitive ? "*****" : valText);
    }
  } // method setColumn

  RequestorEntryWrapper changeRequestor(NameId nameId, String type, String conf,
      PasswordResolver passwordResolver)
          throws CaMgmtException {
    notNull(nameId, "nameId");
    RequestorEntryWrapper requestor = new RequestorEntryWrapper();

    if (MgmtEntry.Requestor.TYPE_PBM.equalsIgnoreCase(type)) {
      if (!StringUtil.startsWithIgnoreCase(conf, "PBE:")) {
        try {
          conf = passwordResolver.protectPassword("PBE", conf.toCharArray());
        } catch (PasswordResolverException ex) {
          throw new CaMgmtException("could not encrypt requestor " + nameId.getName(), ex);
        }
      }
    }

    requestor.setDbEntry(new MgmtEntry.Requestor(nameId, type, conf), passwordResolver);

    if (requestor.getDbEntry().isFaulty()) {
      throw new CaMgmtException("invalid requestor configuration");
    }

    changeIfNotNull("REQUESTOR", col(INT, "ID", nameId.getId()),
        col(STRING, "TYPE", type), col(STRING, "CONF", conf));
    return requestor;
  } // method changeRequestor

  SignerEntryWrapper changeSigner(String name, String type, String conf, String base64Cert,
      CaManagerImpl caManager, SecurityFactory securityFactory)
          throws CaMgmtException {
    notBlank(name, "name");
    notNull(caManager, "caManager");

    MgmtEntry.Signer dbEntry = createSigner(name);
    String tmpType = (type == null ? dbEntry.getType() : type);
    if (conf != null) {
      conf = CaManagerImpl.canonicalizeSignerConf(tmpType, conf, null, securityFactory);
    }

    MgmtEntry.Signer newDbEntry = new MgmtEntry.Signer(name, tmpType,
        (conf == null ? dbEntry.getConf() : conf),
        (base64Cert == null ? dbEntry.getBase64Cert() : base64Cert));
    SignerEntryWrapper responder = caManager.createSigner(newDbEntry);

    changeIfNotNull("SIGNER", col(STRING, "NAME", name), col(STRING, "TYPE", type),
        col(STRING, "CERT", base64Cert), col(STRING, "CONF", conf, false, true));
    return responder;
  } // method changeSigner

  IdentifiedCertPublisher changePublisher(String name, String type, String conf,
      CaManagerImpl caManager)
          throws CaMgmtException {
    notBlank(name, "name");
    notNull(caManager, "caManager");

    MgmtEntry.Publisher currentDbEntry = createPublisher(name);
    MgmtEntry.Publisher dbEntry = new MgmtEntry.Publisher(currentDbEntry.getIdent(),
        (type == null ? currentDbEntry.getType() : type),
        (conf == null ? currentDbEntry.getConf() : conf));
    IdentifiedCertPublisher publisher = caManager.createPublisher(dbEntry);

    changeIfNotNull("PUBLISHER", col(STRING, "NAME", name), col(STRING, "TYPE", type),
        col(STRING, "CONF", conf));
    return publisher;
  } // method changePublisher

  void removeCa(String caName)
      throws CaMgmtException {
    notBlank(caName, "caName");
    final String sql = "DELETE FROM CA WHERE NAME=?";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, caName);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not delelted CA " + caName);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeCa

  void removeCaAlias(String aliasName)
      throws CaMgmtException {
    notBlank(aliasName, "aliasName");
    final String sql = "DELETE FROM CAALIAS WHERE NAME=?";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, aliasName);
      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not remove CA Alias " + aliasName);
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeCaAlias

  void removeCertprofileFromCa(String profileName, String caName)
      throws CaMgmtException {
    notBlank(profileName, "profileName");
    notBlank(caName, "caName");

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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeCertprofileFromCa

  void removeRequestorFromCa(String requestorName, String caName)
      throws CaMgmtException {
    notBlank(requestorName, "requestorName");
    notBlank(caName, "caName");

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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeRequestorFromCa

  void removePublisherFromCa(String publisherName, String caName)
      throws CaMgmtException {
    notBlank(publisherName, "publisherName");
    notBlank(caName, "caName");
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removePublisherFromCa

  void revokeCa(String caName, CertRevocationInfo revocationInfo)
      throws CaMgmtException {
    notBlank(caName, "caName");
    notNull(revocationInfo, "revocationInfo");
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method revokeCa

  void addSigner(MgmtEntry.Signer dbEntry)
      throws CaMgmtException {
    notNull(dbEntry, "dbEntry");
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addSigner

  void unlockCa()
      throws CaMgmtException {
    final String sql = "DELETE FROM SYSTEM_EVENT WHERE NAME='LOCK'";
    Statement stmt = null;
    try {
      stmt = createStatement();
      stmt.execute(sql);
      if (stmt.getUpdateCount() == 0) {
        throw new CaMgmtException("could not unlock CA");
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, null);
    }
  } // method unlockCa

  void unrevokeCa(String caName)
      throws CaMgmtException {
    notBlank(caName, "caName");
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method unrevokeCa

  void addUser(MgmtEntry.AddUser userEntry)
      throws CaMgmtException {
    notNull(userEntry, "userEntry");
    String hashedPassword = PasswordHash.createHash(userEntry.getPassword());
    addUser(userEntry.getIdent().getName(), userEntry.isActive(), hashedPassword);
  } // method addUser

  void addUser(MgmtEntry.User userEntry)
      throws CaMgmtException {
    notNull(userEntry, "userEntry");
    addUser(userEntry.getIdent().getName(), userEntry.isActive(), userEntry.getHashedPassword());
  }

  private void addUser(String name, boolean active, String hashedPassword)
      throws CaMgmtException {
    Integer existingId = getIdForName(sqlSelectUserId, name);
    if (existingId != null) {
      throw new CaMgmtException(concat("user named '", name, " ' already exists"));
    }

    long id = getNextId(Table.TUSER);

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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }

    LOG.info("added user '{}'", name);
  } // method addUser

  void changeUser(MgmtEntry.ChangeUser userEntry)
      throws CaMgmtException {
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

  void removeUserFromCa(String username, String caName)
      throws CaMgmtException {
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeUserFromCa

  void addUserToCa(MgmtEntry.CaHasUser user, NameId ca)
      throws CaMgmtException {
    notNull(user, "user");
    notNull(ca, "ca");

    final NameId userIdent = user.getUserIdent();
    Integer existingId = getIdForName(sqlSelectUserId, userIdent.getName());
    if (existingId == null) {
      throw new CaMgmtException(concat("user '", userIdent.getName(), " ' does not exist"));
    }
    userIdent.setId(existingId);

    PreparedStatement ps = null;
    final String sql = "INSERT INTO CA_HAS_USER (ID,CA_ID,USER_ID, PERMISSION,PROFILES)"
        + " VALUES (?,?,?,?,?)";

    long id = getNextId(Table.CA_HAS_USER);

    try {
      ps = prepareStatement(sql);

      int idx = 1;
      ps.setLong(idx++, id);
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addUserToCa

  Map<String, MgmtEntry.CaHasUser> getCaHasUsersForUser(String user, CaIdNameMap idNameMap)
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

      Map<String, MgmtEntry.CaHasUser> ret = new HashMap<>();
      while (rs.next()) {
        List<String> list = StringUtil.split(rs.getString("PROFILES"), ",");
        Set<String> profiles = (list == null) ? null : new HashSet<>(list);
        MgmtEntry.CaHasUser caHasUser = new MgmtEntry.CaHasUser(new NameId(existingId, user));
        caHasUser.setPermission(rs.getInt("PERMISSION"));
        caHasUser.setProfiles(profiles);

        int caId = rs.getInt("CA_ID");
        String caName = idNameMap.getCaName(caId);

        ret.put(caName, caHasUser);
      }
      return ret;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, rs);
    }
  }  // method getCaHasUsersForUser

  List<MgmtEntry.CaHasUser> getCaHasUsersForCa(String caName, CaIdNameMap idNameMap)
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

      List<MgmtEntry.CaHasUser> ret = new LinkedList<>();
      while (rs.next()) {
        List<String> list = StringUtil.split(rs.getString("PROFILES"), ",");
        Set<String> profiles = (list == null) ? null : new HashSet<>(list);
        MgmtEntry.CaHasUser caHasUser =
            new MgmtEntry.CaHasUser(new NameId(null, rs.getString("NAME")));
        caHasUser.setPermission(rs.getInt("PERMISSION"));
        caHasUser.setProfiles(profiles);

        ret.add(caHasUser);
      }
      return ret;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method getCaHasUsersForCa

  MgmtEntry.User getUser(String username)
      throws CaMgmtException {
    return getUser(username, false);
  }

  MgmtEntry.User getUser(String username, boolean nullable)
      throws CaMgmtException {
    notBlank(username, "username");
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
      return new MgmtEntry.User(ident, rs.getBoolean("ACTIVE"), rs.getString("PASSWORD"));
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method getUser

  private static void setBoolean(PreparedStatement ps, int index, boolean bo)
      throws SQLException {
    ps.setInt(index, bo ? 1 : 0);
  }

  private static String getRealString(String str) {
    return CaManager.NULL.equalsIgnoreCase(str) ? null : str;
  }

  private static String encodeCertchain(List<X509Cert> certs)
      throws CaMgmtException {
    try {
      return X509Util.encodeCertificates(certs.toArray(new X509Cert[0]));
    } catch (CertificateException | IOException ex) {
      throw new CaMgmtException(ex);
    }
  } // method encodeCertchain

  private static List<X509Cert> buildCertChain(X509Cert targetCert,
      List<X509Cert> certs)
          throws CaMgmtException {
    X509Cert[] certchain;
    try {
      certchain = X509Util.buildCertPath(targetCert, certs, false);
    } catch (CertPathBuilderException ex) {
      throw new CaMgmtException(ex);
    }

    if (certchain == null || certs.size() != certchain.length) {
      throw new CaMgmtException("could not build certchain containing all specified certs");
    }
    return Arrays.asList(certchain);
  } // method buildCertChain

  private static X509Cert parseCert(byte[] encodedCert)
      throws CaMgmtException {
    try {
      return X509Util.parseCert(encodedCert);
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not parse certificate", ex);
    }
  } // method parseCert

  private int getNonNullIdForName(String sql, String name)
      throws CaMgmtException {
    Integer id = getIdForName(sql, name);
    if (id != null) {
      return id.intValue();
    }

    throw new CaMgmtException(concat("Found no entry named ",name));
  } // method getNonNullIdForName

  private Integer getIdForName(String sql, String name)
      throws CaMgmtException {
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method getIdForName

  private Map<Integer, String> getIdNameMap(String tableName)
      throws CaMgmtException {
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
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, rs);
    }

    return ret;
  } // method getIdNameMap

  private long getNextId(Table table) throws CaMgmtException {
    try {
      long idInDb = datasource.getMax(null, table.name(), "ID");
      AtomicLong cachedId = cachedIdMap.get(table);
      long nextId = Math.max(idInDb, cachedId.get()) + 1;
      cachedId.set(nextId);
      return nextId;
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }
  }

  private static String concat(String s1, String... strs) {
    return StringUtil.concat(s1, strs);
  }

}
