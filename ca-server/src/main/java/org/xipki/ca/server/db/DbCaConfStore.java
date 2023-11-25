// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.*;
import org.xipki.ca.api.mgmt.entry.*;
import org.xipki.ca.api.mgmt.entry.CaEntry.CaSignerConf;
import org.xipki.ca.server.*;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.mgmt.CaProfileIdAliases;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.pki.OperationException;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.ca.server.CaUtil.*;

/**
 * Execute the database queries to manage CA system.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */
public class DbCaConfStore extends DbCaConfStoreBase implements CaConfStore {

  private static final Logger LOG = LoggerFactory.getLogger(DbCaConfStore.class);

  private final String sqlSelectProfileId;
  private final String sqlSelectProfile;
  private final String sqlSelectPublisherId;
  private final String sqlSelectPublisher;
  private final String sqlSelectRequestorId;
  private final String sqlSelectRequestor;
  private final String sqlSelectSigner;
  private final String sqlSelectKeypairGen;
  private final String sqlSelectCaId;
  private final String sqlSelectCa;
  private final String sqlNextSelectCrlNo;
  private final String sqlSelectSystemEvent;
  private final Map<Table, AtomicLong> cachedIdMap = new HashMap<>();

  public DbCaConfStore(DataSourceWrapper datasource) throws CaMgmtException {
    super(datasource);

    for (Table m : Table.values()) {
      cachedIdMap.put(m, new AtomicLong(0));
    }

    this.sqlSelectProfileId   = buildSelectFirstSql("ID FROM PROFILE WHERE NAME=?");
    this.sqlSelectCaId        = buildSelectFirstSql("ID FROM CA WHERE NAME=?");
    this.sqlSelectPublisherId = buildSelectFirstSql("ID FROM PUBLISHER WHERE NAME=?");
    this.sqlSelectRequestorId = buildSelectFirstSql("ID FROM REQUESTOR WHERE NAME=?");

    this.sqlSelectProfile     = buildSelectFirstSql("ID,TYPE,CONF FROM PROFILE WHERE NAME=?");
    this.sqlSelectPublisher   = buildSelectFirstSql("ID,TYPE,CONF FROM PUBLISHER WHERE NAME=?");
    this.sqlSelectRequestor   = buildSelectFirstSql("ID,TYPE,CONF FROM REQUESTOR WHERE NAME=?");
    this.sqlSelectSigner      = buildSelectFirstSql("TYPE,CERT,CONF FROM SIGNER WHERE NAME=?");
    this.sqlSelectKeypairGen  = buildSelectFirstSql("TYPE,CONF FROM KEYPAIR_GEN WHERE NAME=?");

    this.sqlSelectCa = buildSelectFirstSql("ID,STATUS,NEXT_CRLNO,CRL_SIGNER_NAME,SUBJECT,REV_INFO," +
        "SIGNER_TYPE,SIGNER_CONF,CERT,CERTCHAIN,CONF FROM CA WHERE NAME=?");
    this.sqlNextSelectCrlNo = buildSelectFirstSql("NEXT_CRLNO FROM CA WHERE ID=?");
    this.sqlSelectSystemEvent = buildSelectFirstSql("EVENT_TIME,EVENT_OWNER FROM SYSTEM_EVENT WHERE NAME=?");
  } // constructor

  @Override
  public boolean needsCertStore() {
    return true;
  }

  /**
   * Retrieve the system event.
   * @param eventName Event name
   * @return the System event, may be {@code null}.
   * @throws CaMgmtException
   *            If error occurs.
   */
  public SystemEvent getSystemEvent(String eventName) throws CaMgmtException {
    ResultRow rs = execQuery1PrepStmt0(sqlSelectSystemEvent, col2Str(eventName));
    return (rs == null) ? null : new SystemEvent(eventName, rs.getString("EVENT_OWNER"), getLong(rs, "EVENT_TIME"));
  } // method getSystemEvent

  private void deleteSystemEvent(String eventName) throws CaMgmtException {
    execUpdatePrepStmt0("DELETE FROM SYSTEM_EVENT WHERE NAME=?", col2Str(eventName));
  }

  private void addSystemEvent(SystemEvent systemEvent) throws CaMgmtException {
    final String sql = SqlUtil.buildInsertSql("SYSTEM_EVENT", "NAME,EVENT_TIME,EVENT_TIME2,EVENT_OWNER");

    int num = execUpdatePrepStmt0(sql, col2Str(systemEvent.getName()), col2Long(systemEvent.getEventTime()),
        col2Timestamp(new Timestamp(systemEvent.getEventTime() * 1000L)),  col2Str(systemEvent.getOwner()));

    if (num == 0) {
      throw new CaMgmtException("could not add system event " + systemEvent.getName());
    }

    LOG.info("added system event {}", systemEvent.getName());
  } // method addSystemEvent

  @Override
  public int getDbSchemaVersion() {
    return dbSchemaVersion;
  }

  @Override
  public void changeSystemEvent(SystemEvent systemEvent) throws CaMgmtException {
    deleteSystemEvent(systemEvent.getName());
    addSystemEvent(systemEvent);
  } // method changeSystemEvent

  @Override
  public Map<String, Integer> createCaAliases() throws CaMgmtException {
    Map<String, Integer> map = new HashMap<>();

    List<ResultRow> rows = execQueryStmt0("SELECT NAME,CA_ID FROM CAALIAS");
    for (ResultRow m : rows) {
      map.put(m.getString("NAME"), getInt(m, "CA_ID"));
    }
    return map;
  } // method createCaAliases

  @Override
  public CertprofileEntry createCertprofile(String name) throws CaMgmtException {
    ResultRow rs = Optional.ofNullable(execQuery1PrepStmt0(sqlSelectProfile, col2Str(name)))
        .orElseThrow(() -> new CaMgmtException("unknown Certprofile " + name));

    return new CertprofileEntry(new NameId(getInt(rs, "ID"), name), rs.getString("TYPE"), rs.getString("CONF"));
  } // method createCertprofile

  @Override
  public PublisherEntry createPublisher(String name) throws CaMgmtException {
    ResultRow rs = Optional.ofNullable(execQuery1PrepStmt0(sqlSelectPublisher, col2Str(name))).orElseThrow(
        () -> new CaMgmtException("unknown Publisher " + name));

    return new PublisherEntry(new NameId(getInt(rs, "ID"), name), rs.getString("TYPE"), rs.getString("CONF"));
  } // method createPublisher

  @Override
  public Integer getRequestorId(String requestorName) throws CaMgmtException {
    ResultRow rs = execQuery1PrepStmt0(sqlSelectRequestorId, col2Str(requestorName));
    return (rs == null) ? null : getInt(rs, "ID");
  } // method getRequestorId

  @Override
  public RequestorEntry createRequestor(String name) throws CaMgmtException {
    ResultRow rs = Optional.ofNullable(execQuery1PrepStmt0(sqlSelectRequestor, col2Str(name)))
        .orElseThrow(() -> new CaMgmtException("unknown Requestor " + name));

    return new RequestorEntry(new NameId(getInt(rs, "ID"), name), rs.getString("TYPE"), rs.getString("CONF"));
  } // method createRequestor

  @Override
  public SignerEntry createSigner(String name) throws CaMgmtException {
    ResultRow rs = Optional.ofNullable(execQuery1PrepStmt0(sqlSelectSigner, col2Str(name)))
        .orElseThrow(() -> new CaMgmtException("unknown signer " + name));

    return new SignerEntry(name, rs.getString("TYPE"), rs.getString("CONF"), rs.getString("CERT"));
  } // method createSigner

  @Override
  public KeypairGenEntry createKeypairGen(String name) throws CaMgmtException {
    ResultRow rs = Optional.ofNullable(execQuery1PrepStmt0(sqlSelectKeypairGen, col2Str(name)))
        .orElseThrow(() -> new CaMgmtException("unknown keypair generation " + name));

    return new KeypairGenEntry(name, rs.getString("TYPE"), rs.getString("CONF"));
  } // method createSigner

  @Override
  public CaInfo createCaInfo(String name, CertStore certstore) throws CaMgmtException {
    ResultRow rs = Optional.ofNullable(execQuery1PrepStmt0(sqlSelectCa, col2Str(name)))
        .orElseThrow(() -> new CaMgmtException("unknown CA " + name));

    String encodedConf = rs.getString("CONF");
    CaConfColumn conf = CaConfColumn.decode(encodedConf);

    CaEntry entry = new CaEntry(new NameId(getInt(rs, "ID"), name));

    entry.setNextCrlNo(getLong(rs, "NEXT_CRLNO"));
    entry.setSignerType(rs.getString("SIGNER_TYPE"));
    entry.setSignerConf(rs.getString("SIGNER_CONF"));
    entry.setCaUris(conf.caUris());
    entry.setNumCrls(conf.getNumCrls());
    entry.setExpirationPeriod(conf.getExpirationPeriod());
    entry.setCert(generateCert(rs.getString("CERT")));

    List<X509Cert> certchain = generateCertchain(rs.getString("CERTCHAIN"));
    // validate certchain
    if (CollectionUtil.isNotEmpty(certchain)) {
      buildCertChain(entry.getCert(), certchain);
      entry.setCertchain(certchain);
    }

    entry.setStatus(CaStatus.forName(rs.getString("STATUS")));
    String crlsignerName = rs.getString("CRL_SIGNER_NAME");
    if (StringUtil.isNotBlank(crlsignerName)) {
      entry.setCrlSignerName(crlsignerName);
    }

    String revInfo = rs.getString("REV_INFO");
    CertRevocationInfo revocationInfo = (revInfo == null) ? null : CertRevocationInfo.fromEncoded(revInfo);
    entry.setRevocationInfo(revocationInfo);

    conf.fillBaseCaInfo(entry);

    try {
      return new CaInfo(entry, conf, certstore);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex);
    }
  } // method createCaInfo

  @Override
  public Set<CaHasRequestorEntry> createCaHasRequestors(NameId ca) throws CaMgmtException {
    Map<Integer, String> idNameMap = getIdNameMap("REQUESTOR");

    final String sql = "SELECT REQUESTOR_ID,PERMISSION,PROFILES FROM CA_HAS_REQUESTOR WHERE CA_ID=?";

    List<ResultRow> rows = execQueryPrepStmt0(sql, col2Int(ca.getId()));

    Set<CaHasRequestorEntry> ret = new HashSet<>();
    for (ResultRow rs : rows) {
      int id = getInt(rs, "REQUESTOR_ID");
      String name = idNameMap.get(id);

      List<String> list = StringUtil.split(rs.getString("PROFILES"), ",");
      Set<String> profiles = (list == null) ? null : new HashSet<>(list);
      CaHasRequestorEntry entry = new CaHasRequestorEntry(new NameId(id, name));
      entry.setPermissions(new Permissions(getInt(rs, "PERMISSION")));
      entry.setProfiles(profiles);

      ret.add(entry);
    }

    return ret;
  } // method createCaHasRequestors

  @Override
  public Set<CaProfileIdAliases> createCaHasProfiles(NameId ca) throws CaMgmtException {
    final String sql = "SELECT PROFILE_ID,ALIASES FROM CA_HAS_PROFILE WHERE CA_ID=?";
    List<ResultRow> rows = execQueryPrepStmt0(sql, col2Int(ca.getId()));

    Set<CaProfileIdAliases> ret = new HashSet<>();

    for (ResultRow row : rows) {
      int id = getInt(row, "PROFILE_ID");
      String encodedAliases = row.getString("ALIASES");
      ret.add(new CaProfileIdAliases(id, encodedAliases));
    }

    return ret;
  }

  @Override
  public Set<Integer> createCaHasPublishers(NameId ca) throws CaMgmtException {
    return createCaHasEntities("CA_HAS_PUBLISHER", "PUBLISHER_ID", ca);
  }

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
  } // method getNextId

  @Override
  public void addCa(CaEntry caEntry) throws CaMgmtException {
    Args.notNull(caEntry, "caEntry");

    caEntry.getIdent().setId((int) getNextId(Table.CA));

    String colNames ="ID,NAME,STATUS,NEXT_CRLNO,CRL_SIGNER_NAME,SUBJECT,REV_INFO," +
        "SIGNER_TYPE,SIGNER_CONF,CERT,CERTCHAIN,CONF";

    String sql = SqlUtil.buildInsertSql("CA", colNames);

    byte[] encodedCert = caEntry.getCert().getEncoded();
    List<X509Cert> certchain = caEntry.getCertchain();
    String certchainStr = CollectionUtil.isEmpty(certchain) ? null
        : encodeCertchain(buildCertChain(caEntry.getCert(), certchain));

    CaConfColumn cc = CaConfColumn.fromBaseCaInfo(caEntry);

    String revInfoStr = null;
    if (caEntry.getRevocationInfo() != null) {
      revInfoStr = caEntry.getRevocationInfo().encode();
    }

    List<SqlColumn2> cols = CaUtil.asModifiableList(
        col2Int(caEntry.getIdent().getId()), // ID
        col2Str(caEntry.getIdent().getName()), // NAME
        col2Str(caEntry.getStatus().getStatus()), // STATUS
        col2Long(caEntry.getNextCrlNo()), // NEXT_CRLNO
        col2Str(caEntry.getCrlSignerName()), // CRL_SIGNER_NAME
        col2Str(X509Util.cutText(caEntry.subject(), getMaxX500nameLen())), // SUBJECT
        col2Str(revInfoStr), // REV_INFO
        col2Str(caEntry.getSignerType()), // SIGNER_TYPE
        col2Str(caEntry.getSignerConf()),  // SIGNER_CONF
        col2Str(Base64.encodeToString(encodedCert)), // CERT
        col2Str(certchainStr), // CERTCHAIN
        col2Str(cc.encode())); // CONFCOLUMN

    // insert to table ca
    int num = execUpdatePrepStmt0(sql, cols.toArray(new SqlColumn2[0]));
    if (num == 0) {
      throw new CaMgmtException("could not add CA " + caEntry.getIdent());
    }

    if (LOG.isInfoEnabled()) {
      LOG.info("added CA '{}':\n{}", caEntry.getIdent(), caEntry.toString(false, true));
    }
  } // method addCa

  @Override
  public void addCaAlias(String aliasName, NameId ca) throws CaMgmtException {
    notNulls(aliasName, "aliasName", ca, "ca");
    final String sql = SqlUtil.buildInsertSql("CAALIAS", "NAME,CA_ID");
    int num = execUpdatePrepStmt0(sql, col2Str(aliasName), col2Int(ca.getId()));

    if (num == 0) {
      throw new CaMgmtException("could not add CA alias " + aliasName);
    }
    LOG.info("added CA alias '{}' for CA '{}'", aliasName, ca);
  } // method addCaAlias

  @Override
  public void addCertprofile(CertprofileEntry dbEntry) throws CaMgmtException {
    Args.notNull(dbEntry, "dbEntry");
    final String sql = SqlUtil.buildInsertSql("PROFILE", "ID,NAME,TYPE,CONF");

    dbEntry.getIdent().setId((int) getNextId(Table.PROFILE));

    int num = execUpdatePrepStmt0(sql,
        col2Int(dbEntry.getIdent().getId()), col2Str(dbEntry.getIdent().getName()),
        col2Str(dbEntry.getType()),          col2Str(dbEntry.getConf()));

    if (num == 0) {
      throw new CaMgmtException("could not add certprofile " + dbEntry.getIdent());
    }

    LOG.info("added profile '{}':\n{}", dbEntry.getIdent(), dbEntry);
  } // method addCertprofile

  @Override
  public void addCertprofileToCa(NameId profile, NameId ca, List<String> aliases) throws CaMgmtException {
    notNulls(profile, "profile", ca, "ca");
    final String sql = SqlUtil.buildInsertSql("CA_HAS_PROFILE", "CA_ID,PROFILE_ID,ALIASES");

    String aliasesStr;
    if (CollectionUtil.isEmpty(aliases)) {
      aliasesStr = null;
    } else {
      if (aliases.size() == 1) {
        aliasesStr = aliases.get(0);
      } else {
        StringBuilder sb = new StringBuilder();
        for (String alias : aliases) {
          sb.append(alias).append(",");
        }
        aliasesStr = sb.substring(0, sb.length() - 1);
      }
    }

    int num = execUpdatePrepStmt0(sql, col2Int(ca.getId()), col2Int(profile.getId()), col2Str(aliasesStr));
    if (num == 0) {
      throw new CaMgmtException("could not add profile " + profile + " (aliases " + aliases + ") to CA " +  ca);
    }

    LOG.info("added profile '{}' (aliases {}) to CA '{}'", profile, aliases, ca);
  } // method addCertprofileToCa

  @Override
  public void addPublisherToCa(NameId publisher, NameId ca) throws CaMgmtException {
    notNulls(publisher, "publisher", ca, "ca");

    final String sql = SqlUtil.buildInsertSql("CA_HAS_PUBLISHER", "CA_ID,PUBLISHER_ID");
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

  @Override
  public void addRequestor(RequestorEntry dbEntry) throws CaMgmtException {
    Args.notNull(dbEntry, "dbEntry");

    dbEntry.getIdent().setId((int) getNextId(Table.REQUESTOR));

    final String sql = SqlUtil.buildInsertSql("REQUESTOR", "ID,NAME,TYPE,CONF");
    int num = execUpdatePrepStmt0(sql,
        col2Int(dbEntry.getIdent().getId()), col2Str(dbEntry.getIdent().getName()),
        col2Str(dbEntry.getType()),          col2Str(dbEntry.getConf()));

    if (num == 0) {
      throw new CaMgmtException("could not add requestor " + dbEntry.getIdent());
    }

    if (LOG.isInfoEnabled()) {
      LOG.info("added requestor '{}':\n{}", dbEntry.getIdent(), dbEntry.toString(false));
    }
  } // method addRequestor

  @Override
  public NameId addEmbeddedRequestor(String requestorName) throws CaMgmtException {
    requestorName = requestorName.toLowerCase();

    final String sql = SqlUtil.buildInsertSql("REQUESTOR", "ID,NAME,TYPE,CONF");
    int nextId = (int) getNextId(Table.REQUESTOR);
    String name = "EMBEDDED";

    int num = execUpdatePrepStmt0(sql,
          col2Int(nextId), col2Str(requestorName), col2Str(name), col2Str("DEFAULT"));

    if (num == 0) {
      throw new CaMgmtException("could not add requestor " + requestorName);
    }

    LOG.info("added requestor '{}'", requestorName);
    return new NameId(nextId, name);
  } // method addEmbeddedRequestor

  @Override
  public void addRequestorToCa(CaHasRequestorEntry requestor, NameId ca) throws CaMgmtException {
    notNulls(requestor, "requestor", ca, "ca");

    final String sql = SqlUtil.buildInsertSql("CA_HAS_REQUESTOR", "CA_ID,REQUESTOR_ID,PERMISSION,PROFILES");

    String profilesText = StringUtil.collectionAsString(requestor.getProfiles(), ",");
    final NameId requestorIdent = requestor.getRequestorIdent();

    int num = execUpdatePrepStmt0(sql, col2Int(ca.getId()), col2Int(requestorIdent.getId()),
          col2Int(requestor.getPermissions().getValue()), col2Str(profilesText));

    if (num == 0) {
      throw new CaMgmtException("could not add requestor " + requestorIdent + " to CA " + ca);
    }

    LOG.info("added requestor '{}' to CA '{}': permission: {} ({}); profile: {}",
        requestorIdent, ca, requestor.getPermissions().getValue(), requestor.getPermissions(), profilesText);
  } // method addRequestorToCa

  @Override
  public void addPublisher(PublisherEntry dbEntry) throws CaMgmtException {
    Args.notNull(dbEntry, "dbEntry");
    final String sql = SqlUtil.buildInsertSql("PUBLISHER", "ID,NAME,TYPE,CONF");

    dbEntry.getIdent().setId((int) getNextId(Table.PUBLISHER));
    String name = dbEntry.getIdent().getName();

    int num = execUpdatePrepStmt0(sql, col2Int(dbEntry.getIdent().getId()), col2Str(name),
                col2Str(dbEntry.getType()), col2Str(dbEntry.getConf()));

    if (num == 0) {
      throw new CaMgmtException("could not add publisher " + dbEntry.getIdent());
    }

    LOG.info("added publisher '{}':\n{}", dbEntry.getIdent(), dbEntry);
  } // method addPublisher

  @Override
  public void changeCa(ChangeCaEntry changeCaEntry,
                       CaConfColumn currentCaConfColumn, SecurityFactory securityFactory)
      throws CaMgmtException {
    notNulls(changeCaEntry, "changeCaEntry", currentCaConfColumn, "currentCaConfColumn",
        securityFactory, "securityFactory");

    byte[] encodedCert = changeCaEntry.getEncodedCert();
    if (encodedCert != null) {
      boolean anyCertIssued;
      try {
        anyCertIssued = datasource.columnExists(null, "CERT", "CA_ID", changeCaEntry.getIdent().getId());
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

        ResultRow rs = Optional.ofNullable(execQuery1PrepStmt0(sql, col2Int(changeCaEntry.getIdent().getId())))
            .orElseThrow(() -> new CaMgmtException("unknown CA '" + changeCaEntry.getIdent()));

        caCert = parseCert(Base64.decode(rs.getString("CERT")));
      }

      if (signerType != null || signerConf != null || encodedCert != null) {
        // validate the signer configuration
        final String sql = "SELECT SIGNER_TYPE,SIGNER_CONF FROM CA WHERE ID=?";

        ResultRow rs = Optional.ofNullable(execQuery1PrepStmt0(sql, col2Int(changeCaEntry.getIdent().getId())))
            .orElseThrow(() -> new CaMgmtException("unknown CA '" + changeCaEntry.getIdent()));

        if (signerType == null) {
          signerType = rs.getString("SIGNER_TYPE");
        }

        signerConf = (signerConf == null)
            ? rs.getString("SIGNER_CONF")
            : CaUtil.canonicalizeSignerConf(signerConf);

        try {
          List<CaSignerConf> signerConfs = CaEntry.splitCaSignerConfs(signerConf);
          for (CaSignerConf m : signerConfs) {
            try (ConcurrentContentSigner ignored =
                     securityFactory.createSigner(signerType, new SignerConf(m.getConf()), caCert)) {
            }
          }
        } catch (IOException | XiSecurityException | ObjectCreationException ex) {
          throw new CaMgmtException("could not create signer for CA '"
              + changeCaEntry.getIdent() + "'" + ex.getMessage(), ex);
        }
      }
    } // end if (signerType)

    String subject = null;
    String base64Cert = null;
    if (encodedCert != null) {
      try {
        subject = X509Util.parseCert(encodedCert).getIssuerText();
        base64Cert = Base64.encodeToString(encodedCert);
      } catch (CertificateException ex) {
        throw new CaMgmtException("could not parse the certificate", ex);
      }
    }

    String certchainStr = null;
    if (changeCaEntry.getEncodedCertchain() != null) {
      List<byte[]> encodedCertchain = changeCaEntry.getEncodedCertchain();
      if (encodedCertchain.isEmpty()) {
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

    String status = (changeCaEntry.getStatus() == null) ? null : changeCaEntry.getStatus().name();

    List<SqlColumn> cols = CaUtil.asModifiableList(
        colStr("STATUS", status),    colStr("CRL_SIGNER_NAME", changeCaEntry.getCrlSignerName()),
        colStr("SUBJECT", subject),  colStr("SIGNER_TYPE", signerType),
        colStr("SIGNER_CONF", signerConf, false, true),
        colStr("CERT", base64Cert),  colStr("CERTCHAIN", certchainStr));

    SqlColumn colConfColumn;
    try {
      colConfColumn = buildChangeCaConfColumn(changeCaEntry, currentCaConfColumn);
    } catch (InvalidConfException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }

    if (colConfColumn != null) {
      cols.add(colConfColumn);
    }

    changeIfNotNull("CA", colInt("ID", changeCaEntry.getIdent().getId()),
        cols.toArray(new SqlColumn[0]));
  } // method changeCa

  private SqlColumn buildChangeCaConfColumn(
      ChangeCaEntry changeCaEntry, CaConfColumn currentCaConfColumn) throws InvalidConfException {
    CaConfColumn newCC = currentCaConfColumn.copy();

    if (changeCaEntry.getMaxValidity() != null) {
      newCC.setMaxValidity(changeCaEntry.getMaxValidity());
    }

    String str = changeCaEntry.getExtraControl();
    if (str != null) {
      newCC.setExtraControl(CaManager.NULL.equalsIgnoreCase(str) ? null : new ConfPairs(str));
    }

    if (changeCaEntry.getValidityMode() != null) {
      newCC.setValidityMode(changeCaEntry.getValidityMode());
    }

    CaUris changeUris = changeCaEntry.getCaUris();
    if (changeUris != null) {
      // CAcert URIs
      List<String> uris = changeUris.getCacertUris();
      if (uris != null) {
        newCC.setCacertUris(uris.isEmpty() ? null : uris);
      }

      // CRL URIs
      uris = changeUris.getCrlUris();
      if (uris != null) {
        newCC.setCrlUris(uris.isEmpty() ? null : uris);
      }

      // DeltaCRL URIs
      uris = changeUris.getDeltaCrlUris();
      if (uris != null) {
        newCC.setDeltaCrlUris(uris.isEmpty() ? null : uris);
      }

      // OCSP URIs
      uris = changeUris.getOcspUris();
      if (uris != null) {
        newCC.setOcspUris(uris.isEmpty() ? null : uris);
      }
    }

    // Keypair generation names
    List<String> names = changeCaEntry.getKeypairGenNames();
    if (names != null) {
      newCC.setKeypairGenNames(names.isEmpty() || names.get(0).equalsIgnoreCase(CaManager.NULL) ? null : names);
    }

    // serial number size
    if (changeCaEntry.getSerialNoLen() != null) {
      newCC.setSnSize(changeCaEntry.getSerialNoLen());
    }

    // CRL control
    str = changeCaEntry.getCrlControl();
    if (str != null) {
      newCC.setCrlControl(CaManager.NULL.equalsIgnoreCase(str) ? null : new CrlControl(str));
    }

    // CTLog control
    str = changeCaEntry.getCtlogControl();
    if (str != null) {
      newCC.setCtlogControl(CaManager.NULL.equalsIgnoreCase(str) ? null : new CtlogControl(str));
    }

    if (changeCaEntry.getSaveCert() != null) {
      newCC.setSaveCert(changeCaEntry.getSaveCert());
    }

    if (changeCaEntry.getSaveKeypair() != null) {
      newCC.setSaveKeypair(changeCaEntry.getSaveKeypair());
    }

    List<String> list = changeCaEntry.getPermission();
    if (list != null && !list.isEmpty()) {
      newCC.setPermission(new Permissions(PermissionConstants.toIntPermission(list)));
    }

    if (changeCaEntry.getNumCrls() != null) {
      newCC.setNumCrls(changeCaEntry.getNumCrls());
    }

    if (changeCaEntry.getExpirationPeriod() != null) {
      newCC.setExpirationPeriod(changeCaEntry.getExpirationPeriod());
    }

    if (changeCaEntry.getKeepExpiredCertDays() != null) {
      newCC.setKeepExpiredCertDays(changeCaEntry.getKeepExpiredCertDays());
    }

    str = changeCaEntry.getRevokeSuspendedControl();
    if (str != null) {
      newCC.setRevokeSuspendedControl(CaManager.NULL.equalsIgnoreCase(str) ? null : new RevokeSuspendedControl(str));
    }

    String encodedConf = newCC.encode();
    String encodedOrigConf = currentCaConfColumn.encode();
    if (encodedConf.equals(encodedOrigConf)) {
      return null;
    }

    boolean confIsSensitive = encodedConf.contains("password");
    return colStr("CONF", encodedConf, confIsSensitive, false);
  }

  @Override
  public void commitNextCrlNoIfLess(NameId ca, long nextCrlNo) throws CaMgmtException {
    ResultRow rs = execQuery1PrepStmt0(sqlNextSelectCrlNo, col2Int(ca.getId()));
    long nextCrlNoInDb = getLong(rs, "NEXT_CRLNO");

    if (nextCrlNoInDb < nextCrlNo) {
      execUpdatePrepStmt0("UPDATE CA SET NEXT_CRLNO=? WHERE ID=?", col2Long(nextCrlNo), col2Int(ca.getId()));
    }
  } // method commitNextCrlNoIfLess

  @Override
  public IdentifiedCertprofile changeCertprofile(
      NameId nameId, String type, String conf, CaManagerImpl certprofileManager)
      throws CaMgmtException {
    CertprofileEntry currentDbEntry = createCertprofile(nameId.getName());
    CertprofileEntry newDbEntry = new CertprofileEntry(currentDbEntry.getIdent(),
        str(type, currentDbEntry.getType()), str(conf, currentDbEntry.getConf()));

    IdentifiedCertprofile profile = Optional.ofNullable(certprofileManager.createCertprofile(newDbEntry))
        .orElseThrow(() -> new CaMgmtException("could not create certprofile object"));

    boolean failed = true;
    try {
      changeIfNotNull("PROFILE", colInt("ID", nameId.getId()), colStr("TYPE", type), colStr("CONF", conf));
      failed = false;
      return profile;
    } finally {
      if (failed) {
        profile.close();
      }
    }
  } // method changeCertprofile

  @Override
  public RequestorEntryWrapper changeRequestor(
      NameId nameId, String type, String conf, PasswordResolver passwordResolver)
      throws CaMgmtException {
    Args.notNull(nameId, "nameId");
    RequestorEntryWrapper requestor = new RequestorEntryWrapper();

    requestor.setDbEntry(new RequestorEntry(nameId, type, conf));

    if (requestor.getDbEntry().faulty()) {
      throw new CaMgmtException("invalid requestor configuration");
    }

    changeIfNotNull("REQUESTOR", colInt("ID", nameId.getId()), colStr("TYPE", type), colStr("CONF", conf));
    return requestor;
  } // method changeRequestor

  @Override
  public SignerEntry changeSigner(
      String name, String type, String conf, String base64Cert, CaManagerImpl signerManager)
      throws CaMgmtException {
    Args.notNull(signerManager, "signerManager");

    SignerEntry dbEntry = createSigner(Args.notBlank(name, "name"));
    String tmpType = (type == null ? dbEntry.getType() : type);
    if (conf != null) {
      conf = CaUtil.canonicalizeSignerConf(conf);
    }

    SignerEntry signer = new SignerEntry(name, tmpType, (conf == null ? dbEntry.getConf() : conf),
        (base64Cert == null ? dbEntry.base64Cert() : base64Cert));
    signerManager.createSigner(signer);

    changeIfNotNull("SIGNER", colStr("NAME", name), colStr("TYPE", type),
        colStr("CERT", base64Cert), colStr("CONF", conf, false, true));
    return signer;
  } // method changeSigner

  @Override
  public KeypairGenEntryWrapper changeKeypairGen(String name, String type, String conf, CaManagerImpl manager)
      throws CaMgmtException {
    Args.notNull(manager, "manager");

    KeypairGenEntry dbEntry = createKeypairGen(Args.notBlank(name, "name"));
    String tmpType = (type == null ? dbEntry.getType() : type);

    KeypairGenEntry newDbEntry = new KeypairGenEntry(name, tmpType, (conf == null ? dbEntry.getConf() : conf));
    KeypairGenEntryWrapper wrapper = manager.createKeypairGenerator(newDbEntry);

    changeIfNotNull("KEYPAIR_GEN", colStr("NAME", name), colStr("TYPE", type),
            colStr("CONF", conf, true, false));
    return wrapper;
  } // method changeKeypairGen

  @Override
  public IdentifiedCertPublisher changePublisher(String name, String type, String conf, CaManagerImpl publisherManager)
      throws CaMgmtException {
    Args.notNull(publisherManager, "publisherManager");

    PublisherEntry currentDbEntry = createPublisher(Args.notBlank(name, "name"));
    PublisherEntry dbEntry = new PublisherEntry(currentDbEntry.getIdent(),
        (type == null ? currentDbEntry.getType() : type), (conf == null ? currentDbEntry.getConf() : conf));
    IdentifiedCertPublisher publisher = publisherManager.createPublisher(dbEntry);

    changeIfNotNull("PUBLISHER", colStr("NAME", name), colStr("TYPE", type), colStr("CONF", conf));
    return publisher;
  } // method changePublisher

  @Override
  public void removeCaAlias(String aliasName) throws CaMgmtException {
    Args.notBlank(aliasName, "aliasName");
    int num = execUpdatePrepStmt0("DELETE FROM CAALIAS WHERE NAME=?", col2Str(aliasName));
    if (num == 0) {
      throw new CaMgmtException("could not remove CA Alias " + aliasName);
    }
  } // method removeCaAlias

  @Override
  public void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException {
    Args.notBlank(profileName, "profileName");
    Args.notBlank(caName, "caName");

    removeEntityFromCa("profile", profileName, caName, sqlSelectProfileId,
        "DELETE FROM CA_HAS_PROFILE WHERE CA_ID=? AND PROFILE_ID=?");
  } // method removeCertprofileFromCa

  @Override
  public void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException {
    Args.notBlank(requestorName, "requestorName");
    Args.notBlank(caName, "caName");

    removeEntityFromCa("requestor", requestorName, caName, sqlSelectRequestorId,
        "DELETE FROM CA_HAS_REQUESTOR WHERE CA_ID=? AND REQUESTOR_ID=?");
  } // method removeRequestorFromCa

  @Override
  public void removePublisherFromCa(String publisherName, String caName) throws CaMgmtException {
    removeEntityFromCa("publisher",
        Args.notBlank(publisherName, "publisherName"),
        Args.notBlank(caName, "caName"),
        sqlSelectPublisherId,
        "DELETE FROM CA_HAS_PUBLISHER WHERE CA_ID=? AND PUBLISHER_ID=?");
  } // method removePublisherFromCa

  @Override
  public void removeDbSchema(String name) throws CaMgmtException {
    Args.notBlank(name, "name");
    final String sql = "DELETE FROM DBSCHEMA WHERE NAME=?";

    int num = execUpdatePrepStmt0(sql, col2Str(name));
    if (num == 0) {
      throw new CaMgmtException("could not delete DBSCHEMA " + name);
    }
  }

  private void removeEntityFromCa(String desc, String name, String caName, String sqlSelectId, String sqlRemove)
      throws CaMgmtException {
    Integer id = Optional.ofNullable(getIdForName(sqlSelectId, name))
        .orElseThrow(() -> new CaMgmtException(String.format("unknown %s %s ", desc, name)));

    int caId = getNonNullIdForName(sqlSelectCaId, caName);
    int num = execUpdatePrepStmt0(sqlRemove, col2Int(caId), col2Int(id));
    if (num == 0) {
      throw new CaMgmtException(String.format("could not remove %s from CA %s", name, caName));
    }
  } // method removeEntityFromCa

  @Override
  public void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException {
    Args.notBlank(caName, "caName");
    Args.notNull(revocationInfo, "revocationInfo");
    int num = execUpdatePrepStmt0("UPDATE CA SET REV_INFO=? WHERE NAME=?",
                col2Str(revocationInfo.encode()), col2Str(caName));
    if (num == 0) {
      throw new CaMgmtException("could not revoke CA " + caName);
    }
  } // method revokeCa

  @Override
  public void addKeypairGen(KeypairGenEntry dbEntry) throws CaMgmtException {
    Args.notNull(dbEntry, "dbEntry");

    int num = execUpdatePrepStmt0("INSERT INTO KEYPAIR_GEN (NAME,TYPE,CONF) VALUES (?,?,?)",
            col2Str(dbEntry.getName()), col2Str(dbEntry.getType()), col2Str(dbEntry.getConf()));

    if (num == 0) {
      throw new CaMgmtException("could not add keypair generation " + dbEntry.getName());
    }

    LOG.info("added keypair generation: \n{}", dbEntry.toString(true));
  } // method addSigner

  @Override
  public void addSigner(SignerEntry dbEntry) throws CaMgmtException {
    Args.notNull(dbEntry, "dbEntry");

    int num = execUpdatePrepStmt0(SqlUtil.buildInsertSql("SIGNER", "NAME,TYPE,CERT,CONF"),
            col2Str(dbEntry.getName()),    col2Str(dbEntry.getType()),
            col2Str(dbEntry.base64Cert()), col2Str(dbEntry.getConf()));

    if (num == 0) {
      throw new CaMgmtException("could not add signer " + dbEntry.getName());
    }

    LOG.info("added signer: {}", dbEntry.toString(false, true));
  } // method addSigner

  @Override
  public void unlockCa() throws CaMgmtException {
    int num;
    try {
      num = execUpdateStmt0("DELETE FROM SYSTEM_EVENT WHERE NAME='LOCK'");
    } catch (CaMgmtException ex) {
      throw new CaMgmtException("could not unlock CA", ex);
    }

    if (num == 0) {
      LOG.info("CA system is not locked");
    } else {
      LOG.info("Unlocked CA system");
    }
  } // method unlockCa

  @Override
  public void unrevokeCa(String caName) throws CaMgmtException {
    Args.notBlank(caName, "caName");
    LOG.info("Unrevoking of CA '{}'", caName);

    int num = execUpdatePrepStmt0("UPDATE CA SET REV_INFO=? WHERE NAME=?", col2Str(null), col2Str(caName));
    if (num == 0) {
      throw new CaMgmtException("could not unrevoke CA " + caName);
    }
  } // method unrevokeCa

  @Override
  public void addDbSchema(String name, String value) throws CaMgmtException {
    final String sql = SqlUtil.buildInsertSql("DBSCHEMA", "NAME,VALUE2");
    int num = execUpdatePrepStmt0(sql, col2Str(name), col2Str(value));
    if (num == 0) {
      throw new CaMgmtException("could not add DBSCHEMA " + name);
    }
    LOG.info("added DBSCHEMA '{}'", name);
  }

  @Override
  public void changeDbSchema(String name, String value) throws CaMgmtException {
    String sql = "UPDATE DBSCHEMA SET VALUE2=? WHERE NAME=?";
    int num = execUpdatePrepStmt0(sql, col2Str(value), col2Str(name));

    if (num == 0) {
      throw new CaMgmtException("could not update DBSCHEMA " + name);
    }
    LOG.info("added DBSCHEMA '{}'", name);
  }

  @Override
  public Map<String, String> getDbSchemas() throws CaMgmtException {
    Args.notNull(datasource, "datasource");

    final String sql = "SELECT NAME,VALUE2 FROM DBSCHEMA";

    Map<String, String> dbSchemas = new HashMap<>();
    PreparedStatement stmt = null;
    ResultSet rs = null;

    try {
      stmt = Optional.ofNullable(datasource.prepareStatement(sql))
          .orElseThrow(() -> new DataAccessException("could not create statement"));

      rs = stmt.executeQuery();
      while (rs.next()) {
        dbSchemas.put(rs.getString("NAME"), rs.getString("VALUE2"));
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }

    return dbSchemas;
  }

  @Override
  public List<String> getCaNames() throws CaMgmtException {
    return namesFromTable("CA");
  }

  @Override
  public boolean deleteCa(String name) throws CaMgmtException {
    return deleteRowWithName(name, "CA");
  }

  @Override
  public List<String> getKeyPairGenNames() throws CaMgmtException {
    return namesFromTable("KEYPAIR_GEN");
  }

  @Override
  public boolean deleteKeyPairGen(String name) throws CaMgmtException {
    return deleteRowWithName(name, "KEYPAIR_GEN");
  }

  @Override
  public List<String> getProfileNames() throws CaMgmtException {
    return namesFromTable("PROFILE");
  }

  @Override
  public boolean deleteProfile(String name) throws CaMgmtException {
    return deleteRowWithName(name, "PROFILE");
  }

  @Override
  public List<String> getPublisherNames() throws CaMgmtException {
    return namesFromTable("PUBLISHER");
  }

  @Override
  public boolean deletePublisher(String name) throws CaMgmtException {
    return deleteRowWithName(name, "PUBLISHER");
  }

  @Override
  public List<String> getRequestorNames() throws CaMgmtException {
    return namesFromTable("REQUESTOR");
  }

  @Override
  public boolean deleteRequestor(String name) throws CaMgmtException {
    return deleteRowWithName(name, "REQUESTOR");
  }

  @Override
  public List<String> getSignerNames() throws CaMgmtException {
    return namesFromTable("SIGNER");
  }

  @Override
  public boolean deleteSigner(String name) throws CaMgmtException {
    return deleteRowWithName(name, "SIGNER");
  }

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

  private static int getInt(ResultRow rs, String label) {
    return rs.getInt(label);
  }

  private static long getLong(ResultRow rs, String label) {
    return rs.getLong(label);
  }

}
