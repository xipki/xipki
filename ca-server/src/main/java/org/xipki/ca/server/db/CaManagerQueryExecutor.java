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

package org.xipki.ca.server.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.mgmt.*;
import org.xipki.ca.api.mgmt.entry.*;
import org.xipki.ca.api.mgmt.entry.CaEntry.CaSignerConf;
import org.xipki.ca.server.*;
import org.xipki.ca.server.db.CertStore.SystemEvent;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.*;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.sql.Timestamp;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.ca.server.CaUtil.*;
import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.StringUtil.concat;

/**
 * Execute the database queries to manage CA system.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
public class CaManagerQueryExecutor extends CaManagerQueryExecutorBase {

  private static final Logger LOG = LoggerFactory.getLogger(CaManagerQueryExecutor.class);

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

  public CaManagerQueryExecutor(DataSourceWrapper datasource) {
    super(datasource);

    for (Table m : Table.values()) {
      cachedIdMap.put(m, new AtomicLong(0));
    }

    this.sqlSelectProfileId   = buildSelectFirstSql("ID FROM PROFILE WHERE NAME=?");
    this.sqlSelectCaId        = buildSelectFirstSql("ID FROM CA WHERE NAME=?");
    this.sqlSelectPublisherId = buildSelectFirstSql("ID FROM PUBLISHER WHERE NAME=?");
    this.sqlSelectRequestorId = buildSelectFirstSql("ID FROM REQUESTOR WHERE NAME=?");
    this.sqlSelectUserId      = buildSelectFirstSql("ID FROM TUSER WHERE NAME=?");

    this.sqlSelectProfile     = buildSelectFirstSql("ID,TYPE,CONF FROM PROFILE WHERE NAME=?");
    this.sqlSelectPublisher   = buildSelectFirstSql("ID,TYPE,CONF FROM PUBLISHER WHERE NAME=?");
    this.sqlSelectRequestor   = buildSelectFirstSql("ID,TYPE,CONF FROM REQUESTOR WHERE NAME=?");
    this.sqlSelectSigner      = buildSelectFirstSql("TYPE,CERT,CONF FROM SIGNER WHERE NAME=?");

    this.sqlSelectCa = buildSelectFirstSql("ID,SN_SIZE,NEXT_CRLNO,STATUS,MAX_VALIDITY,CERT,"
        + "CERTCHAIN,SIGNER_TYPE,CMP_RESPONDER_NAME,SCEP_RESPONDER_NAME,CRL_SIGNER_NAME,"
        + "CMP_CONTROL,CRL_CONTROL,SCEP_CONTROL,CTLOG_CONTROL,"
        + "PROTOCOL_SUPPORT,SAVE_REQ,PERMISSION,NUM_CRLS,KEEP_EXPIRED_CERT_DAYS,"
        + "EXPIRATION_PERIOD,REV_INFO,VALIDITY_MODE,CA_URIS,EXTRA_CONTROL,SIGNER_CONF,"
        + "DHPOC_CONTROL,REVOKE_SUSPENDED_CONTROL FROM CA WHERE NAME=?");

    this.sqlNextSelectCrlNo = buildSelectFirstSql("NEXT_CRLNO FROM CA WHERE ID=?");

    this.sqlSelectSystemEvent = buildSelectFirstSql(
        "EVENT_TIME,EVENT_OWNER FROM SYSTEM_EVENT WHERE NAME=?");

    this.sqlSelectUser = buildSelectFirstSql("ID,ACTIVE,PASSWORD FROM TUSER WHERE NAME=?");
  } // constructor

  /**
   * Retrieve the system event.
   * @param eventName Event name
   * @return the System event, may be {@code null}.
   * @throws CaMgmtException
   *            If error occurs.
   */
  public SystemEvent getSystemEvent(String eventName) throws CaMgmtException {
    ResultRow rs = execQuery1PrepStmt0(sqlSelectSystemEvent, col2Str(eventName));
    return (rs == null) ? null
              : new SystemEvent(eventName, rs.getString("EVENT_OWNER"), getLong(rs, "EVENT_TIME"));
  } // method getSystemEvent

  private void deleteSystemEvent(String eventName) throws CaMgmtException {
    execUpdatePrepStmt0("DELETE FROM SYSTEM_EVENT WHERE NAME=?", col2Str(eventName));
  } // method deleteSystemEvent

  private void addSystemEvent(SystemEvent systemEvent) throws CaMgmtException {
    final String sql =
        "INSERT INTO SYSTEM_EVENT (NAME,EVENT_TIME,EVENT_TIME2,EVENT_OWNER) VALUES (?,?,?,?)";

    int num = execUpdatePrepStmt0(sql,
        col2Str(systemEvent.getName()), col2Long(systemEvent.getEventTime()),
        col2Timestamp(new Timestamp(systemEvent.getEventTime() * 1000L)),
        col2Str(systemEvent.getOwner()));

    if (num == 0) {
      throw new CaMgmtException("could not add system event " + systemEvent.getName());
    }

    LOG.info("added system event {}", systemEvent.getName());
  } // method addSystemEvent

  public void changeSystemEvent(SystemEvent systemEvent) throws CaMgmtException {
    deleteSystemEvent(systemEvent.getName());
    addSystemEvent(systemEvent);
  } // method changeSystemEvent

  public Map<String, Integer> createCaAliases() throws CaMgmtException {
    Map<String, Integer> map = new HashMap<>();

    List<ResultRow> rows = execQueryStmt0("SELECT NAME,CA_ID FROM CAALIAS");
    for (ResultRow m : rows) {
      map.put(m.getString("NAME"), getInt(m, "CA_ID"));
    }
    return map;
  } // method createCaAliases

  public CertprofileEntry createCertprofile(String name) throws CaMgmtException {
    ResultRow rs = execQuery1PrepStmt0(sqlSelectProfile, col2Str(name));

    if (rs == null) {
      throw new CaMgmtException("unknown CA " + name);
    }

    return new CertprofileEntry(new NameId(getInt(rs, "ID"), name),
        rs.getString("TYPE"), rs.getString("CONF"));
  } // method createCertprofile

  public PublisherEntry createPublisher(String name) throws CaMgmtException {
    ResultRow rs = execQuery1PrepStmt0(sqlSelectPublisher, col2Str(name));

    if (rs == null) {
      throw new CaMgmtException("unkown Publisher " + name);
    }

    return new PublisherEntry(new NameId(getInt(rs, "ID"), name),
        rs.getString("TYPE"), rs.getString("CONF"));
  } // method createPublisher

  public Integer getRequestorId(String requestorName) throws CaMgmtException {
    ResultRow rs = execQuery1PrepStmt0(sqlSelectRequestorId, col2Str(requestorName));
    return (rs == null) ? null : getInt(rs, "ID");
  } // method getRequestorId

  public RequestorEntry createRequestor(String name) throws CaMgmtException {
    ResultRow rs = execQuery1PrepStmt0(sqlSelectRequestor, col2Str(name));

    if (rs == null) {
      throw new CaMgmtException("unknown Requestor " + name);
    }

    return new RequestorEntry(new NameId(getInt(rs, "ID"), name),
        rs.getString("TYPE"), rs.getString("CONF"));
  } // method createRequestor

  public SignerEntry createSigner(String name) throws CaMgmtException {
    ResultRow rs = execQuery1PrepStmt0(sqlSelectSigner, col2Str(name));

    if (rs == null) {
      throw new CaMgmtException("unknown signer " + name);
    }

    return new SignerEntry(name, rs.getString("TYPE"), rs.getString("CONF"), rs.getString("CERT"));
  } // method createSigner

  public CaInfo createCaInfo(String name, CertStore certstore)
      throws CaMgmtException {
    ResultRow rs = execQuery1PrepStmt0(sqlSelectCa, col2Str(name));
    if (rs == null) {
      throw new CaMgmtException("uknown CA " + name);
    }

    String caUrisText = rs.getString("CA_URIS");
    CaUris caUris = (caUrisText == null) ? null : CaUris.decode(caUrisText);
    int snSize = getInt(rs, "SN_SIZE");
    if (snSize > CaManager.MAX_SERIALNUMBER_SIZE) {
      snSize = CaManager.MAX_SERIALNUMBER_SIZE;
    } else if (snSize < CaManager.MIN_SERIALNUMBER_SIZE) {
      snSize = CaManager.MIN_SERIALNUMBER_SIZE;
    }

    CaEntry entry = new CaEntry(new NameId(getInt(rs, "ID"), name), snSize,
        getLong(rs, "NEXT_CRLNO"), rs.getString("SIGNER_TYPE"), rs.getString("SIGNER_CONF"),
        caUris, getInt(rs, "NUM_CRLS"), getInt(rs, "EXPIRATION_PERIOD"));

    entry.setCert(generateCert(rs.getString("CERT")));
    entry.setDhpopControl(rs.getString("DHPOC_CONTROL"));
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
    entry.setKeepExpiredCertInDays(getInt(rs, "KEEP_EXPIRED_CERT_DAYS"));

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
    if (StringUtil.isNotBlank(cmpcontrol)) {
      try {
        entry.setCmpControl(new CmpControl(cmpcontrol));
      } catch (InvalidConfException ex) {
        throw new CaMgmtException("invalid CMP_CONTROL: " + cmpcontrol);
      }
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

    ProtocolSupport protocolSupport = new ProtocolSupport(rs.getString("PROTOCOL_SUPPORT"));
    if (protocolSupport.isCmp()) {
      if (entry.getCmpControl() == null) {
        LOG.warn("CA {}: CMP is supported but CMP_CONTROL is not set, disable the CMP support",
                name);
        protocolSupport.setCmp(false);
      }
    }
    entry.setProtocolSupport(protocolSupport);

    entry.setSaveRequest((getInt(rs, "SAVE_REQ") != 0));
    entry.setPermission(getInt(rs, "PERMISSION"));

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
  } // method createCaInfo

  public Set<CaHasRequestorEntry> createCaHasRequestors(NameId ca) throws CaMgmtException {
    Map<Integer, String> idNameMap = getIdNameMap("REQUESTOR");

    final String sql =
        "SELECT REQUESTOR_ID,RA,PERMISSION,PROFILES FROM CA_HAS_REQUESTOR WHERE CA_ID=?";

    List<ResultRow> rows = execQueryPrepStmt0(sql, col2Int(ca.getId()));

    Set<CaHasRequestorEntry> ret = new HashSet<>();
    for (ResultRow rs : rows) {
      int id = getInt(rs, "REQUESTOR_ID");
      String name = idNameMap.get(id);

      List<String> list = StringUtil.split(rs.getString("PROFILES"), ",");
      Set<String> profiles = (list == null) ? null : new HashSet<>(list);
      CaHasRequestorEntry entry = new CaHasRequestorEntry(new NameId(id, name));
      entry.setRa(getBoolean(rs, "RA"));
      entry.setPermission(getInt(rs, "PERMISSION"));
      entry.setProfiles(profiles);

      ret.add(entry);
    }

    return ret;
  } // method createCaHasRequestors

  public Set<Integer> createCaHasProfiles(NameId ca) throws CaMgmtException {
    return createCaHasEntities("CA_HAS_PROFILE", "PROFILE_ID", ca);
  } // method createCaHasProfiles

  public Set<Integer> createCaHasPublishers(NameId ca) throws CaMgmtException {
    return createCaHasEntities("CA_HAS_PUBLISHER", "PUBLISHER_ID", ca);
  } // method createCaHasPublishers

  private Set<Integer> createCaHasEntities(String table, String column, NameId ca)
      throws CaMgmtException {
    final String sql = "SELECT " + column + " FROM " + table + " WHERE CA_ID=?";

    List<ResultRow> rows = execQueryPrepStmt0(sql, col2Int(ca.getId()));

    Set<Integer> ret = new HashSet<>();
    for (ResultRow rs : rows) {
      ret.add(getInt(rs, column));
    }

    return ret;
  } // method createCaHasEntities

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

  public void addCa(CaEntry caEntry) throws CaMgmtException {
    notNull(caEntry, "caEntry");

    caEntry.getIdent().setId((int) getNextId(Table.CA));

    final String sql = "INSERT INTO CA (ID,NAME,SUBJECT,SN_SIZE,NEXT_CRLNO,STATUS,CA_URIS,"//7
        + "MAX_VALIDITY,CERT,CERTCHAIN,SIGNER_TYPE,CRL_SIGNER_NAME,"//5
        + "CMP_RESPONDER_NAME,SCEP_RESPONDER_NAME,CRL_CONTROL,CMP_CONTROL,SCEP_CONTROL,"//5
        + "CTLOG_CONTROL,PROTOCOL_SUPPORT,SAVE_REQ,PERMISSION,"//6
        + "NUM_CRLS,EXPIRATION_PERIOD,KEEP_EXPIRED_CERT_DAYS,VALIDITY_MODE,EXTRA_CONTROL,"//5
        + "SIGNER_CONF,DHPOC_CONTROL,REVOKE_SUSPENDED_CONTROL) "
        + "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    CaUris caUris = caEntry.getCaUris();
    byte[] encodedCert = caEntry.getCert().getEncoded();
    List<X509Cert> certchain = caEntry.getCertchain();
    String certchainStr = CollectionUtil.isEmpty(certchain) ? null
        : encodeCertchain(buildCertChain(caEntry.getCert(), certchain));

    CrlControl crlControl = caEntry.getCrlControl();
    CmpControl cmpControl = caEntry.getCmpControl();
    ScepControl scepControl = caEntry.getScepControl();
    CtlogControl ctlogControl = caEntry.getCtlogControl();
    ProtocolSupport protocolSupport = caEntry.getProtocoSupport();
    ConfPairs extraControl = caEntry.getExtraControl();
    String encodedExtraCtrl = (extraControl == null) ? null : extraControl.getEncoded();
    RevokeSuspendedControl revokeSuspended = caEntry.getRevokeSuspendedControl();

    // insert to table ca
    int num = execUpdatePrepStmt0(sql,
        col2Int(caEntry.getIdent().getId()),         col2Str(caEntry.getIdent().getName()),
        col2Str(caEntry.getSubject()),               col2Int(caEntry.getSerialNoLen()),
        col2Long(caEntry.getNextCrlNumber()),        col2Str(caEntry.getStatus().getStatus()),
        col2Str((caUris == null) ? null : caEntry.getCaUris().getEncoded()),
        col2Str(caEntry.getMaxValidity().toString()),
        col2Str(Base64.encodeToString(encodedCert)), col2Str(certchainStr),
        col2Str(caEntry.getSignerType()),            col2Str(caEntry.getCrlSignerName()),
        col2Str(caEntry.getCmpResponderName()),      col2Str(caEntry.getScepResponderName()),

        col2Str((crlControl == null      ? null : crlControl.getConf())),
        col2Str((cmpControl == null      ? null : cmpControl.getConf())),
        col2Str((scepControl == null     ? null : scepControl.getConf())),
        col2Str((ctlogControl == null    ? null : ctlogControl.getConf())),
        col2Str((protocolSupport == null ? null : protocolSupport.getEncoded())),

        col2Bool(caEntry.isSaveRequest()),           col2Int(caEntry.getPermission()),
        col2Int(caEntry.getNumCrls()),               col2Int(caEntry.getExpirationPeriod()),
        col2Int(caEntry.getKeepExpiredCertInDays()), col2Str(caEntry.getValidityMode().name()),
        col2Str(StringUtil.isBlank(encodedExtraCtrl) ? null : encodedExtraCtrl),
        col2Str(caEntry.getSignerConf()),            col2Str(caEntry.getDhpopControl()),
        col2Str(revokeSuspended == null ? null : revokeSuspended.getConf()));

    if (num == 0) {
      throw new CaMgmtException("could not add CA " + caEntry.getIdent());
    }

    if (LOG.isInfoEnabled()) {
      LOG.info("add CA '{}': {}", caEntry.getIdent(), caEntry.toString(false, true));
    }
  } // method addCa

  public void addCaAlias(String aliasName, NameId ca) throws CaMgmtException {
    notNulls(aliasName, "aliasName", ca, "ca");

    final String sql = "INSERT INTO CAALIAS (NAME,CA_ID) VALUES (?,?)";
    int num = execUpdatePrepStmt0(sql, col2Str(aliasName), col2Int(ca.getId()));

    if (num == 0) {
      throw new CaMgmtException("could not add CA alias " + aliasName);
    }
    LOG.info("added CA alias '{}' for CA '{}'", aliasName, ca);
  } // method addCaAlias

  public void addCertprofile(CertprofileEntry dbEntry) throws CaMgmtException {
    notNull(dbEntry, "dbEntry");
    final String sql = "INSERT INTO PROFILE (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";

    dbEntry.getIdent().setId((int) getNextId(Table.PROFILE));

    int num = execUpdatePrepStmt0(sql,
        col2Int(dbEntry.getIdent().getId()), col2Str(dbEntry.getIdent().getName()),
        col2Str(dbEntry.getType()),          col2Str(dbEntry.getConf()));

    if (num == 0) {
      throw new CaMgmtException("could not add certprofile " + dbEntry.getIdent());
    }

    LOG.info("added profile '{}': {}", dbEntry.getIdent(), dbEntry);
  } // method addCertprofile

  public void addCertprofileToCa(NameId profile, NameId ca) throws CaMgmtException {
    notNulls(profile, "profile", ca, "ca");

    final String sql = "INSERT INTO CA_HAS_PROFILE (CA_ID,PROFILE_ID) VALUES (?,?)";
    addEntityToCa("profile", profile, ca, sql);
  } // method addCertprofileToCa

  public void addPublisherToCa(NameId publisher, NameId ca) throws CaMgmtException {
    notNulls(publisher, "publisher", ca, "ca");

    final String sql = "INSERT INTO CA_HAS_PUBLISHER (CA_ID,PUBLISHER_ID) VALUES (?,?)";
    addEntityToCa("publisher", publisher, ca, sql);
  } // method addPublisherToCa

  private void addEntityToCa(String desc, NameId entity, NameId ca, String sql)
      throws CaMgmtException {
    int num = execUpdatePrepStmt0(sql, col2Int(ca.getId()), col2Int(entity.getId()));
    if (num == 0) {
      throw new CaMgmtException("could not add " + desc + " " + entity + " to CA " +  ca);
    }

    LOG.info("added {} '{}' to CA '{}'", desc, entity, ca);
  } // method addPublisherToCa

  public void addRequestor(RequestorEntry dbEntry) throws CaMgmtException {
    notNull(dbEntry, "dbEntry");

    dbEntry.getIdent().setId((int) getNextId(Table.REQUESTOR));

    final String sql = "INSERT INTO REQUESTOR (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";
    int num = execUpdatePrepStmt0(sql,
        col2Int(dbEntry.getIdent().getId()), col2Str(dbEntry.getIdent().getName()),
        col2Str(dbEntry.getType()),          col2Str(dbEntry.getConf()));

    if (num == 0) {
      throw new CaMgmtException("could not add requestor " + dbEntry.getIdent());
    }

    if (LOG.isInfoEnabled()) {
      LOG.info("added requestor '{}': {}", dbEntry.getIdent(), dbEntry.toString(false));
    }
  } // method addRequestor

  public void addEmbeddedRequestor(String requestorName) throws CaMgmtException {
    requestorName = requestorName.toLowerCase();

    String sql = "INSERT INTO REQUESTOR (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";
    int nextId = (int) getNextId(Table.REQUESTOR);

    int num = execUpdatePrepStmt0(sql,
          col2Int(nextId), col2Str(requestorName), col2Str("EMBEDDED"), col2Str("DEFAULT"));

    if (num == 0) {
      throw new CaMgmtException("could not add requestor " + requestorName);
    }
    LOG.info("added requestor '{}'", requestorName);
  } // method addRequestorIfNeeded

  public void addRequestorToCa(CaHasRequestorEntry requestor, NameId ca) throws CaMgmtException {
    notNulls(requestor, "requestor", ca, "ca");

    final String sql = "INSERT INTO CA_HAS_REQUESTOR (CA_ID,REQUESTOR_ID,RA, PERMISSION,PROFILES)"
        + " VALUES (?,?,?,?,?)";

    String profilesText = StringUtil.collectionAsString(requestor.getProfiles(), ",");
    final NameId requestorIdent = requestor.getRequestorIdent();

    int num = execUpdatePrepStmt0(sql,
          col2Int(ca.getId()), col2Int(requestorIdent.getId()), col2Bool(requestor.isRa()),
          col2Int(requestor.getPermission()), col2Str(profilesText));

    if (num == 0) {
      throw new CaMgmtException("could not add requestor " + requestorIdent + " to CA " + ca);
    }

    LOG.info("added requestor '{}' to CA '{}': ra: {}; permission: {}; profile: {}",
        requestorIdent, ca, requestor.isRa(), requestor.getPermission(), profilesText);
  } // method addRequestorToCa

  public void addPublisher(PublisherEntry dbEntry) throws CaMgmtException {
    notNull(dbEntry, "dbEntry");
    final String sql = "INSERT INTO PUBLISHER (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";

    dbEntry.getIdent().setId((int) getNextId(Table.PUBLISHER));
    String name = dbEntry.getIdent().getName();

    int num = execUpdatePrepStmt0(sql, col2Int(dbEntry.getIdent().getId()), col2Str(name),
                col2Str(dbEntry.getType()), col2Str(dbEntry.getConf()));

    if (num == 0) {
      throw new CaMgmtException("could not add publisher " + dbEntry.getIdent());
    }

    LOG.info("added publisher '{}': {}", dbEntry.getIdent(), dbEntry);
  } // method addPublisher

  public void changeCa(ChangeCaEntry changeCaEntry, CaEntry currentCaEntry,
      SecurityFactory securityFactory) throws CaMgmtException {
    notNulls(changeCaEntry, "changeCaEntry", securityFactory, "securityFactory");

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

        ResultRow rs = execQuery1PrepStmt0(sql, col2Int(changeCaEntry.getIdent().getId()));
        if (rs == null) {
          throw new CaMgmtException("unknown CA '" + changeCaEntry.getIdent());
        }

        caCert = parseCert(Base64.decode(rs.getString("CERT")));
      }

      if (signerType != null || signerConf != null || encodedCert != null) {
        // validate the signer configuration
        final String sql = "SELECT SIGNER_TYPE,SIGNER_CONF FROM CA WHERE ID=?";

        ResultRow rs = execQuery1PrepStmt0(sql, col2Int(changeCaEntry.getIdent().getId()));

        if (rs == null) {
          throw new CaMgmtException("unknown CA '" + changeCaEntry.getIdent());
        }

        if (signerType == null) {
          signerType = rs.getString("SIGNER_TYPE");
        }

        if (signerConf == null) {
          signerConf = rs.getString("SIGNER_CONF");
        } else {
          signerConf = CaUtil.canonicalizeSignerConf(
              signerType, signerConf, null, securityFactory);
        }

        try {
          List<CaSignerConf> signerConfs = CaEntry.splitCaSignerConfs(signerConf);
          for (CaSignerConf m : signerConfs) {
            securityFactory.createSigner(signerType, new SignerConf(m.getConf()), caCert);
          }
        } catch (XiSecurityException | ObjectCreationException ex) {
          throw new CaMgmtException("could not create signer for CA '"
              + changeCaEntry.getIdent() + "'" + ex.getMessage(), ex);
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
        : new ConfPairs(changeCaEntry.getExtraControl()).getEncoded(); // check also the validity
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

    changeIfNotNull("CA", colInt("ID", changeCaEntry.getIdent().getId()),
        colInt("SN_SIZE", changeCaEntry.getSerialNoLen()), colStr("STATUS", status),
        colStr("SUBJECT", subject),          colStr("CERT", base64Cert),
        colStr("CERTCHAIN", certchainStr),   colStr("CA_URIS", caUrisStr),
        colStr("MAX_VALIDITY", maxValidity), colStr("SIGNER_TYPE", signerType),
        colStr("CRL_SIGNER_NAME", changeCaEntry.getCrlSignerName()),
        colStr("CMP_RESPONDER_NAME", changeCaEntry.getCmpResponderName()),
        colStr("SCEP_RESPONDER_NAME", changeCaEntry.getScepResponderName()),
        colStr("CMP_CONTROL", changeCaEntry.getCmpControl()),
        colStr("CRL_CONTROL", changeCaEntry.getCrlControl()),
        colStr("SCEP_CONTROL", changeCaEntry.getScepControl()),
        colStr("CTLOG_CONTROL", changeCaEntry.getCtlogControl()),
        colStr("PROTOCOL_SUPPORT", protocolSupportStr),
        colBool("SAVE_REQ", changeCaEntry.getSaveRequest()),
        colInt("PERMISSION", changeCaEntry.getPermission()),
        colInt("NUM_CRLS", changeCaEntry.getNumCrls()),
        colInt("EXPIRATION_PERIOD", changeCaEntry.getExpirationPeriod()),
        colInt("KEEP_EXPIRED_CERT_DAYS", changeCaEntry.getKeepExpiredCertInDays()),
        colStr("VALIDITY_MODE", validityMode), colStr("EXTRA_CONTROL", extraControl),
        colStr("SIGNER_CONF", signerConf, false, true),
        colStr("DHPOC_CONTROL", changeCaEntry.getDhpopControl(), false, true),
        colStr("REVOKE_SUSPENDED_CONTROL", changeCaEntry.getRevokeSuspendedControl()));
  } // method changeCa

  public void commitNextCrlNoIfLess(NameId ca, long nextCrlNo) throws CaMgmtException {
    ResultRow rs = execQuery1PrepStmt0(sqlNextSelectCrlNo, col2Int(ca.getId()));
    long nextCrlNoInDb = getLong(rs, "NEXT_CRLNO");

    if (nextCrlNoInDb < nextCrlNo) {
      execUpdatePrepStmt0("UPDATE CA SET NEXT_CRLNO=? WHERE ID=?",
          col2Long(nextCrlNo), col2Int(ca.getId()));
    }
  } // method commitNextCrlNoIfLess

  public IdentifiedCertprofile changeCertprofile(NameId nameId, String type, String conf,
      CaManagerImpl certprofileManager) throws CaMgmtException {
    CertprofileEntry currentDbEntry = createCertprofile(nameId.getName());
    CertprofileEntry newDbEntry = new CertprofileEntry(currentDbEntry.getIdent(),
        str(type, currentDbEntry.getType()), str(conf, currentDbEntry.getConf()));

    IdentifiedCertprofile profile = certprofileManager.createCertprofile(newDbEntry);
    if (profile == null) {
      throw new CaMgmtException("could not create certprofile object");
    }

    boolean failed = true;
    try {
      changeIfNotNull("PROFILE", colInt("ID", nameId.getId()), colStr("TYPE", type),
          colStr("CONF", conf));
      failed = false;
      return profile;
    } finally {
      if (failed) {
        profile.close();
      }
    }
  } // method changeCertprofile

  public RequestorEntryWrapper changeRequestor(NameId nameId, String type, String conf,
      PasswordResolver passwordResolver) throws CaMgmtException {
    notNull(nameId, "nameId");
    RequestorEntryWrapper requestor = new RequestorEntryWrapper();

    if (RequestorEntry.TYPE_PBM.equalsIgnoreCase(type)) {
      if (!StringUtil.startsWithIgnoreCase(conf, "PBE:")) {
        try {
          conf = passwordResolver.protectPassword("PBE", conf.toCharArray());
        } catch (PasswordResolverException ex) {
          throw new CaMgmtException(
              "could not encrypt password of requestor " + nameId.getName(), ex);
        }
      }
    }

    requestor.setDbEntry(new RequestorEntry(nameId, type, conf), passwordResolver);

    if (requestor.getDbEntry().isFaulty()) {
      throw new CaMgmtException("invalid requestor configuration");
    }

    changeIfNotNull("REQUESTOR", colInt("ID", nameId.getId()),
        colStr("TYPE", type), colStr("CONF", conf));
    return requestor;
  } // method changeRequestor

  public SignerEntryWrapper changeSigner(String name, String type, String conf, String base64Cert,
      CaManagerImpl signerManager, SecurityFactory securityFactory) throws CaMgmtException {
    notBlank(name, "name");
    notNull(signerManager, "signerManager");

    SignerEntry dbEntry = createSigner(name);
    String tmpType = (type == null ? dbEntry.getType() : type);
    if (conf != null) {
      conf = CaUtil.canonicalizeSignerConf(tmpType, conf, null, securityFactory);
    }

    SignerEntry newDbEntry = new SignerEntry(name, tmpType,
        (conf == null ? dbEntry.getConf() : conf),
        (base64Cert == null ? dbEntry.getBase64Cert() : base64Cert));
    SignerEntryWrapper responder = signerManager.createSigner(newDbEntry);

    changeIfNotNull("SIGNER", colStr("NAME", name), colStr("TYPE", type),
        colStr("CERT", base64Cert), colStr("CONF", conf, false, true));
    return responder;
  } // method changeSigner

  public IdentifiedCertPublisher changePublisher(String name, String type, String conf,
      CaManagerImpl publisherManager) throws CaMgmtException {
    notBlank(name, "name");
    notNull(publisherManager, "publisherManager");

    PublisherEntry currentDbEntry = createPublisher(name);
    PublisherEntry dbEntry = new PublisherEntry(currentDbEntry.getIdent(),
        (type == null ? currentDbEntry.getType() : type),
        (conf == null ? currentDbEntry.getConf() : conf));
    IdentifiedCertPublisher publisher = publisherManager.createPublisher(dbEntry);

    changeIfNotNull("PUBLISHER", colStr("NAME", name), colStr("TYPE", type), colStr("CONF", conf));
    return publisher;
  } // method changePublisher

  public void removeCa(String caName)
      throws CaMgmtException {
    notBlank(caName, "caName");
    final String sql = "DELETE FROM CA WHERE NAME=?";

    int num = execUpdatePrepStmt0(sql, col2Str(caName));
    if (num == 0) {
      throw new CaMgmtException("could not delelted CA " + caName);
    }
  } // method removeCa

  public void removeCaAlias(String aliasName) throws CaMgmtException {
    notBlank(aliasName, "aliasName");
    int num = execUpdatePrepStmt0("DELETE FROM CAALIAS WHERE NAME=?", col2Str(aliasName));
    if (num == 0) {
      throw new CaMgmtException("could not remove CA Alias " + aliasName);
    }
  } // method removeCaAlias

  public void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException {
    notBlank(profileName, "profileName");
    notBlank(caName, "caName");

    removeEntityFromCa("profile", profileName, caName, sqlSelectProfileId,
        "DELETE FROM CA_HAS_PROFILE WHERE CA_ID=? AND PROFILE_ID=?");
  } // method removeCertprofileFromCa

  public void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException {
    notBlank(requestorName, "requestorName");
    notBlank(caName, "caName");

    removeEntityFromCa("requestor", requestorName, caName, sqlSelectRequestorId,
        "DELETE FROM CA_HAS_REQUESTOR WHERE CA_ID=? AND REQUESTOR_ID=?");
  } // method removeRequestorFromCa

  public void removePublisherFromCa(String publisherName, String caName) throws CaMgmtException {
    notBlank(publisherName, "publisherName");
    notBlank(caName, "caName");

    removeEntityFromCa("publisher", publisherName, caName, sqlSelectPublisherId,
        "DELETE FROM CA_HAS_PUBLISHER WHERE CA_ID=? AND PUBLISHER_ID=?");
  } // method removePublisherFromCa

  public void removeUserFromCa(String username, String caName) throws CaMgmtException {
    notBlank(username, "username");
    notBlank(caName, "caName");

    removeEntityFromCa("user", username, caName, sqlSelectUserId,
        "DELETE FROM CA_HAS_USER WHERE CA_ID=? AND USER_ID=?");
  } // method removeUserFromCa

  private void removeEntityFromCa(String desc, String name, String caName,
      String sqlSelectId, String sqlRemove) throws CaMgmtException {
    Integer id = getIdForName(sqlSelectId, name);
    if (id == null) {
      throw new CaMgmtException(String.format("unknown %s %s ", desc, name));
    }

    int caId = getNonNullIdForName(sqlSelectCaId, caName);

    int num = execUpdatePrepStmt0(sqlRemove, col2Int(caId), col2Int(id));
    if (num == 0) {
      throw new CaMgmtException(String.format("could not remove %s from CA %s", name, caName));
    }
  } // method removeUserFromCa

  public void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException {
    notBlank(caName, "caName");
    notNull(revocationInfo, "revocationInfo");
    int num = execUpdatePrepStmt0("UPDATE CA SET REV_INFO=? WHERE NAME=?",
                col2Str(revocationInfo.getEncoded()), col2Str(caName));
    if (num == 0) {
      throw new CaMgmtException("could not revoke CA " + caName);
    }
  } // method revokeCa

  public void addSigner(SignerEntry dbEntry) throws CaMgmtException {
    notNull(dbEntry, "dbEntry");

    int num = execUpdatePrepStmt0(
            "INSERT INTO SIGNER (NAME,TYPE,CERT,CONF) VALUES (?,?,?,?)",
            col2Str(dbEntry.getName()),       col2Str(dbEntry.getType()),
            col2Str(dbEntry.getBase64Cert()), col2Str(dbEntry.getConf()));

    if (num == 0) {
      throw new CaMgmtException("could not add signer " + dbEntry.getName());
    }

    LOG.info("added signer: {}", dbEntry.toString(false, true));
  } // method addSigner

  public void unlockCa() throws CaMgmtException {
    int num = execUpdateStmt0("DELETE FROM SYSTEM_EVENT WHERE NAME='LOCK'");
    if (num == 0) {
      throw new CaMgmtException("could not unlock CA");
    }
  } // method unlockCa

  public void unrevokeCa(String caName) throws CaMgmtException {
    notBlank(caName, "caName");
    LOG.info("Unrevoking of CA '{}'", caName);

    int num = execUpdatePrepStmt0("UPDATE CA SET REV_INFO=? WHERE NAME=?",
                col2Str(null), col2Str(caName));
    if (num == 0) {
      throw new CaMgmtException("could not unrevoke CA " + caName);
    }
  } // method unrevokeCa

  public void addUser(AddUserEntry userEntry) throws CaMgmtException {
    notNull(userEntry, "userEntry");
    String hashedPassword = PasswordHash.createHash(userEntry.getPassword());
    addUser(userEntry.getIdent().getName(), userEntry.isActive(), hashedPassword);
  } // method addUser

  public void addUser(UserEntry userEntry) throws CaMgmtException {
    notNull(userEntry, "userEntry");
    addUser(userEntry.getIdent().getName(), userEntry.isActive(), userEntry.getHashedPassword());
  }

  private void addUser(String name, boolean active, String hashedPassword) throws CaMgmtException {
    Integer existingId = getIdForName(sqlSelectUserId, name);
    if (existingId != null) {
      throw new CaMgmtException(concat("user named '", name, " ' already exists"));
    }

    long id = getNextId(Table.TUSER);

    int num = execUpdatePrepStmt0("INSERT INTO TUSER (ID,NAME,ACTIVE,PASSWORD) VALUES (?,?,?,?)",
            col2Long(id), col2Str(name), col2Bool(active), col2Str(hashedPassword));
    if (num == 0) {
      throw new CaMgmtException("could not add user " + name);
    }
    LOG.info("added user '{}'", name);
  } // method addUser

  public void changeUser(ChangeUserEntry userEntry) throws CaMgmtException {
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

    changeIfNotNull("TUSER", colInt("ID", existingId), colBool("ACTIVE", userEntry.getActive()),
        colStr("PASSWORD", hashedPassword, true, false));
  } // method changeUser

  public void addUserToCa(CaHasUserEntry user, NameId ca) throws CaMgmtException {
    notNulls(user, "user", ca, "ca");

    final NameId userIdent = user.getUserIdent();
    Integer existingId = getIdForName(sqlSelectUserId, userIdent.getName());
    if (existingId == null) {
      throw new CaMgmtException(concat("user '", userIdent.getName(), " ' does not exist"));
    }
    userIdent.setId(existingId);

    long id = getNextId(Table.CA_HAS_USER);
    String profilesText = StringUtil.collectionAsString(user.getProfiles(), ",");

    int num = execUpdatePrepStmt0(
            "INSERT INTO CA_HAS_USER (ID,CA_ID,USER_ID, PERMISSION,PROFILES) VALUES (?,?,?,?,?)",
            col2Long(id), col2Int(ca.getId()), col2Int(userIdent.getId()),
            col2Int(user.getPermission()), col2Str(profilesText));

    if (num == 0) {
      throw new CaMgmtException("could not add user " + userIdent + " to CA " + ca);
    }

    LOG.info("added user '{}' to CA '{}': permission: {}; profile: {}",
        userIdent, ca, user.getPermission(), profilesText);
  } // method addUserToCa

  public Map<String, CaHasUserEntry> getCaHasUsersForUser(String user, CaIdNameMap idNameMap)
      throws CaMgmtException {
    Integer existingId = getIdForName(sqlSelectUserId, user);
    if (existingId == null) {
      throw new CaMgmtException(concat("user '", user, " ' does not exist"));
    }

    final String sql = "SELECT CA_ID,PERMISSION,PROFILES FROM CA_HAS_USER WHERE USER_ID=?";

    List<ResultRow> rows = execQueryPrepStmt0(sql, col2Int(existingId));

    Map<String, CaHasUserEntry> ret = new HashMap<>();
    for (ResultRow rs : rows) {
      List<String> list = StringUtil.split(rs.getString("PROFILES"), ",");
      Set<String> profiles = (list == null) ? null : new HashSet<>(list);
      CaHasUserEntry caHasUser = new CaHasUserEntry(new NameId(existingId, user));
      caHasUser.setPermission(getInt(rs, "PERMISSION"));
      caHasUser.setProfiles(profiles);

      int caId = getInt(rs, "CA_ID");
      String caName = idNameMap.getCaName(caId);

      ret.put(caName, caHasUser);
    }

    return ret;
  }  // method getCaHasUsersForUser

  public List<CaHasUserEntry> getCaHasUsersForCa(String caName, CaIdNameMap idNameMap)
      throws CaMgmtException {
    NameId caIdent = idNameMap.getCa(caName);
    if (caIdent == null) {
      throw new CaMgmtException("unknown CA " + caName);
    }

    final String sql = "SELECT NAME,PERMISSION,PROFILES FROM CA_HAS_USER INNER JOIN TUSER"
        + " ON CA_ID=? AND TUSER.ID=CA_HAS_USER.USER_ID";

    List<ResultRow> rows = execQueryPrepStmt0(sql, col2Int(caIdent.getId()));

    List<CaHasUserEntry> ret = new LinkedList<>();
    for (ResultRow rs : rows) {
      List<String> list = StringUtil.split(rs.getString("PROFILES"), ",");
      Set<String> profiles = (list == null) ? null : new HashSet<>(list);
      CaHasUserEntry caHasUser = new CaHasUserEntry(new NameId(null, rs.getString("NAME")));
      caHasUser.setPermission(getInt(rs, "PERMISSION"));
      caHasUser.setProfiles(profiles);

      ret.add(caHasUser);
    }
    return ret;
  } // method getCaHasUsersForCa

  public UserEntry getUser(String username) throws CaMgmtException {
    return getUser(username, false);
  }

  public UserEntry getUser(String username, boolean nullable) throws CaMgmtException {
    notBlank(username, "username");
    NameId ident = new NameId(null, username);

    ResultRow rs = execQuery1PrepStmt0(sqlSelectUser, col2Str(ident.getName()));
    if (rs == null) {
      if (nullable) {
        return null;
      } else {
        throw new CaMgmtException("unknown user " + username);
      }
    }

    ident.setId(getInt(rs, "ID"));
    return new UserEntry(ident, getBoolean(rs, "ACTIVE"), rs.getString("PASSWORD"));
  } // method getUser

  private static X509Cert generateCert(String b64Cert) throws CaMgmtException {
    return (b64Cert == null) ? null : parseCert(Base64.decode(b64Cert));
  } // method generateCert

  private static List<X509Cert> generateCertchain(String encodedCertchain) throws CaMgmtException {
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

  private static boolean getBoolean(ResultRow rs, String label) {
    return rs.getBoolean(label);
  }

  private static int getInt(ResultRow rs, String label) {
    return rs.getInt(label);
  }

  private static long getLong(ResultRow rs, String label) {
    return rs.getLong(label);
  }

}
