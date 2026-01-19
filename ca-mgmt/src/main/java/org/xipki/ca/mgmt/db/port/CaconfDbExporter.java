// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.mgmt.CaConfType;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.CtlogControl;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.RevokeSuspendedControl;
import org.xipki.ca.api.mgmt.entry.BaseCaInfo;
import org.xipki.ca.api.mgmt.entry.CaConfColumn;
import org.xipki.ca.api.profile.ctrl.ValidityMode;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.datasource.DataAccessException;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.io.FileOrBinary;
import org.xipki.util.io.FileOrValue;
import org.xipki.util.misc.StringUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Database exporter of CA configuration.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class CaconfDbExporter extends DbPorter {

  CaconfDbExporter(DataSourceWrapper datasource, String destDir,
                   AtomicBoolean stopMe)
      throws DataAccessException {
    super(datasource, destDir, stopMe);
  }

  public void export() throws Exception {
    CaConfType.CaSystem caconf = new CaConfType.CaSystem();

    System.out.println("exporting CA configuration from database");

    exportDbSchema(caconf);
    exportSigner(caconf);
    exportRequestor(caconf);
    exportPublisher(caconf);
    exportProfile(caconf);

    exportCa(caconf);

    if (dbSchemaVersion >= 7) {
      exportKeypairGen(caconf);
    }

    try (OutputStream os = Files.newOutputStream(
        Paths.get(baseDir, FILENAME_CA_CONFIGURATION))) {
      String json = JsonBuilder.toPrettyJson(caconf.toCodec());
      os.write(StringUtil.toUtf8Bytes(json));
    }
    System.out.println(" exported CA configuration from database");
  } // method export

  private void exportRequestor(CaConfType.CaSystem caconf)
      throws DataAccessException, IOException {
    System.out.print("    exporting table REQUESTOR ... ");
    boolean succ = false;
    List<CaConfType.Requestor> requestors = new LinkedList<>();
    caconf.setRequestors(requestors);

    final String sql = "SELECT ID,NAME,TYPE,CONF FROM REQUESTOR";

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      rs = stmt.executeQuery();

      while (rs.next()) {
        String name = rs.getString("NAME");

        CaConfType.Requestor requestor = new CaConfType.Requestor(
            null, name, rs.getString("TYPE"),
            buildFileOrValue(rs.getString("CONF"),
                "ca-conf/cert-requestor-" + name + ".conf"));
        requestor.setId(rs.getInt("ID"));
        requestors.add(requestor);
      }

      caconf.setRequestors(requestors);
      succ = true;
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method exportRequestor

  private void exportDbSchema(CaConfType.CaSystem caconf)
      throws DataAccessException {
    System.out.print("    exporting table DBSCHEMA ... ");
    boolean succ = false;
    final String sql = "SELECT NAME,VALUE2 FROM DBSCHEMA";

    Map<String, String> dbSchemas = new HashMap<>();
    caconf.setDbSchemas(dbSchemas);

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      rs = stmt.executeQuery();

      while (rs.next()) {
        String name = rs.getString("NAME");
        String value = rs.getString("VALUE2");
        dbSchemas.put(name, value);
      }
      succ = true;
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method exportDbSchema

  private void exportSigner(CaConfType.CaSystem caconf)
      throws DataAccessException, IOException {
    System.out.print("    exporting table SIGNER ... ");
    boolean succ = false;
    List<CaConfType.Signer> signers = new LinkedList<>();
    caconf.setSigners(signers);

    final String sql = "SELECT NAME,TYPE,CONF,CERT FROM SIGNER";

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      rs = stmt.executeQuery();

      while (rs.next()) {
        String name = rs.getString("NAME");

        CaConfType.Signer signer = new CaConfType.Signer(null, name,
            rs.getString("TYPE"),
            buildFileOrValue(rs.getString("CONF"),
                "ca-conf/conf-signer-" + name),
            buildFileOrBase64Binary(rs.getString("CERT"),
                "ca-conf/cert-signer-" + name + ".der"));

        signers.add(signer);
      }

      caconf.setSigners(signers);
      succ = true;
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method exportSigner

  private void exportKeypairGen(CaConfType.CaSystem caconf)
      throws DataAccessException, IOException {
    System.out.print("    exporting table KEYPAIR_GEN ... ");
    boolean succ = false;

    List<CaConfType.NameTypeConf> keypairGens = new LinkedList<>();
    caconf.setKeypairGens(keypairGens);
    final String sql = "SELECT NAME,TYPE,CONF FROM KEYPAIR_GEN";

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      rs = stmt.executeQuery();

      while (rs.next()) {
        String name = rs.getString("NAME");
        CaConfType.NameTypeConf entry = new CaConfType.NameTypeConf(null, name,
            rs.getString("TYPE"),
            buildFileOrValue(rs.getString("CONF"),
                "ca-conf/conf-publisher-" + name));

        keypairGens.add(entry);
      }

      caconf.setKeypairGens(keypairGens);
      succ = true;
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method exportKeypairGen

  private void exportPublisher(CaConfType.CaSystem caconf)
      throws DataAccessException, IOException {
    System.out.print("    exporting table PUBLISHER ... ");
    boolean succ = false;
    List<CaConfType.NameTypeConf> publishers = new LinkedList<>();
    caconf.setPublishers(publishers);
    final String sql = "SELECT ID,NAME,TYPE,CONF FROM PUBLISHER";

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      rs = stmt.executeQuery();

      while (rs.next()) {
        String name = rs.getString("NAME");

        CaConfType.NameTypeConf publisher = new CaConfType.NameTypeConf(
            null, name, rs.getString("TYPE"),
            buildFileOrValue(rs.getString("CONF"),
                "ca-conf/conf-publisher-" + name));

        publisher.setId(rs.getInt("ID"));
        publishers.add(publisher);
      }

      caconf.setPublishers(publishers);
      succ = true;
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method exportPublisher

  private void exportProfile(CaConfType.CaSystem caconf)
      throws DataAccessException, IOException {
    System.out.print("    exporting table PROFILE ... ");
    boolean succ = false;

    List<CaConfType.NameTypeConf> profiles = new LinkedList<>();
    caconf.setProfiles(profiles);
    final String sql = "SELECT ID,NAME,TYPE,CONF FROM PROFILE";

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      rs = stmt.executeQuery();

      while (rs.next()) {
        String name = rs.getString("NAME");

        CaConfType.NameTypeConf profile = new CaConfType.NameTypeConf(
            null, name, rs.getString("TYPE"),
            buildFileOrValue(rs.getString("CONF"),
                "ca-conf/certprofile-" + name));

        profile.setId(rs.getInt("ID"));
        profiles.add(profile);
      }

      caconf.setProfiles(profiles);
      succ = true;
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method exportProfile

  private void exportCa(CaConfType.CaSystem caconf)
      throws DataAccessException, IOException, InvalidConfException {
    System.out.print("    exporting table CA ... ");
    boolean succ = false;

    caconf.setCas(new LinkedList<>());

    // caAliases
    Map<String, Integer> aliasToCaIdMap = getCaAliases();
    Map<Integer, List<String>> caHassPublishersMap =
        getCaHasPublishers(caconf.getPublishers());

    // caHasRequestors
    Map<Integer, List<CaConfType.CaHasRequestor>> caHasRequestorsMap =
        getCaHasRequestors(caconf.getRequestors());

    // caHasProfiles
    Map<Integer, List<String>> caHasProfilesMap =
        getCaHasProfiles(caconf.getProfiles());

    String columns = "SELECT ID,NAME,STATUS,NEXT_CRLNO,CRL_SIGNER_NAME,"
        + "REV_INFO,SIGNER_TYPE,SIGNER_CONF,CERT,CERTCHAIN";
    if (dbSchemaVersion >= 7) {
      columns += ",CONF";
    } else {
      columns += ",SN_SIZE,CA_URIS,MAX_VALIDITY,PERMISSION,NUM_CRLS," +
          "EXPIRATION_PERIOD,VALIDITY_MODE,CRL_CONTROL,CTLOG_CONTROL," +
          "REVOKE_SUSPENDED_CONTROL,KEEP_EXPIRED_CERT_DAYS,EXTRA_CONTROL";
    }

    final String sql = columns + " FROM CA";

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      rs = stmt.executeQuery();

      while (rs.next()) {
        int id = rs.getInt("ID");

        String name = rs.getString("NAME");
        String signerType = rs.getString("SIGNER_TYPE");
        FileOrValue signerConf =
            buildFileOrValue(rs.getString("SIGNER_CONF"),
                "ca-conf/signerconf-ca-" + name);

        FileOrBinary cert = buildFileOrBase64Binary(rs.getString("CERT"),
            "ca-conf/cert-ca-" + name + ".der");

        List<FileOrBinary> certchainConf = null;
        String encodedCertchain = rs.getString("CERTCHAIN");
        if (StringUtil.isNotBlank(encodedCertchain)) {
          List<X509Cert> certchain;
          try {
            certchain = X509Util.listCertificates(encodedCertchain);
          } catch (CertificateException e) {
            throw new InvalidConfException(
                "error parsing CERTCHAIN of CA " + name);
          }

          certchainConf = new ArrayList<>(certchain.size());
          for (int i = 0; i < certchain.size(); i++) {
            byte[] certBytes = certchain.get(i).getEncoded();
            certchainConf.add(buildFileOrBinary(certBytes,
                "ca-conf/ca-" + name + "-certchain-" + i + ".der"));
          }
        }

        CaConfColumn ccc = getCaConfColumn(rs);
        BaseCaInfo base = new BaseCaInfo(signerType, ccc.getPermissions());
        adoptConfColumn(base, ccc);

        CaConfType.CaInfo ci = new CaConfType.CaInfo(base,
            signerConf, cert, certchainConf);

        base.setNextCrlNo(rs.getLong("NEXT_CRLNO"));
        base.setStatus(CaStatus.forName(rs.getString("STATUS")));

        String revInfoStr = rs.getString("REV_INFO");
        if (revInfoStr != null) {
          base.setRevocationInfo(CertRevocationInfo.fromEncoded(revInfoStr));
        }
        base.setCrlSignerName(rs.getString("CRL_SIGNER_NAME"));

        List<String> aliases = new LinkedList<>();
        for (Map.Entry<String, Integer> m : aliasToCaIdMap.entrySet()) {
          if (m.getValue() == id) {
            aliases.add(m.getKey());
          }
        }

        if (!aliases.isEmpty()) {
          aliases = null;
        }

        CaConfType.Ca ca = new CaConfType.Ca(null, name, ci, aliases,
            caHasProfilesMap.get(id), caHasRequestorsMap.get(id),
            caHassPublishersMap.get(id));
        caconf.getCas().add(ca);

        ca.setId(id);
      }

      succ = true;
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method exportCa

  private CaConfColumn getCaConfColumn(ResultSet rs)
      throws SQLException, InvalidConfException {
    if (dbSchemaVersion >= 7) {
      String confColumn = rs.getString("CONF");
      return CaConfColumn.decode(confColumn); // validate the confColumn
    }

    CaConfColumn ccc = new CaConfColumn();
    ccc.setSnSize(rs.getInt("SN_SIZE"));

    String str = rs.getString("CA_URIS");
    if (StringUtil.isNotBlank(str)) {
      CaUris caUris = CaUris.decode(str);
      ccc.setCacertUris(caUris.getCacertUris());
      ccc.setCrlUris(caUris.getCrlUris());
      ccc.setDeltaCrlUris(caUris.getDeltaCrlUris());
      ccc.setOcspUris(caUris.getOcspUris());
    }

    str = rs.getString("MAX_VALIDITY");
    if (StringUtil.isNotBlank(str)) {
      ccc.setMaxValidity(Validity.getInstance(str));
    }

    str = rs.getString("CRL_CONTROL");
    if (StringUtil.isNotBlank(str)) {
      ccc.setCrlControl(new CrlControl(str));
    }

    str = rs.getString("CTLOG_CONTROL");
    if (StringUtil.isNotBlank(str)) {
      ccc.setCtlogControl(new CtlogControl(str));
    }

    ccc.setPermissions(new Permissions(rs.getInt("PERMISSION")));
    ccc.setExpirationPeriod(rs.getInt("EXPIRATION_PERIOD"));
    ccc.setKeepExpiredCertDays(rs.getInt("KEEP_EXPIRED_CERT_DAYS"));

    str = rs.getString("VALIDITY_MODE");
    if (StringUtil.isNotBlank(str)) {
      ccc.setValidityMode(ValidityMode.forName(str));
    }

    str = rs.getString("EXTRA_CONTROL");
    if (StringUtil.isNotBlank(str)) {
      ccc.setExtraControl(new ConfPairs(str));
    }

    ccc.setNumCrls(rs.getInt("NUM_CRLS"));

    str = rs.getString("REVOKE_SUSPENDED_CONTROL");
    if (StringUtil.isNotBlank(str)) {
      ccc.setRevokeSuspendedControl(new RevokeSuspendedControl(str));
    }

    ccc.setKeypairGenNames(Collections.singletonList("software"));
    ccc.setSaveCert(true);
    ccc.setSaveKeypair(false);

    return ccc;
  }

  public void adoptConfColumn(BaseCaInfo base, CaConfColumn cc) {
    // CA URIS
    if (cc.getCacertUris() != null || cc.getCrlUris() != null
        || cc.getDeltaCrlUris() != null || cc.getOcspUris() != null) {
      base.setCaUris(new CaUris(cc.getCacertUris(), cc.getOcspUris(),
          cc.getCrlUris(), cc.getDeltaCrlUris()));
    }

    base.setCrlControl(cc.getCrlControl());
    base.setCtlogControl(cc.getCtlogControl());
    base.setExtraControl(cc.getExtraControl());
    base.setRevokeSuspendedControl(cc.getRevokeSuspendedControl());

    base.setSnSize(cc.getSnSize());
    base.setMaxValidity(cc.getMaxValidity());
    base.setKeypairGenNames(cc.getKeypairGenNames());
    base.setSaveCert(cc.isSaveCert());
    base.setSaveKeypair(cc.isSaveKeypair());
    base.setNumCrls(cc.getNumCrls());
    base.setExpirationPeriod(cc.getExpirationPeriod());
    base.setKeepExpiredCertDays(cc.getKeepExpiredCertDays());
    cc.setValidityMode(cc.getValidityMode());
  }

  private Map<String, Integer> getCaAliases() throws DataAccessException {
    Map<String, Integer> ret = new HashMap<>();
    final String sql = "SELECT NAME,CA_ID FROM CAALIAS";

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      rs = stmt.executeQuery();

      while (rs.next()) {
        ret.put(rs.getString("NAME"), rs.getInt("CA_ID"));
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    return ret;
  }

  private Map<Integer, List<String>> getCaHasPublishers(
      List<CaConfType.NameTypeConf> publishers) throws DataAccessException {
    Map<Integer, String> publisherIdToNameMap = idToNameMap(publishers);
    Map<Integer, List<String>> ret = new HashMap<>();
    final String sql = "SELECT CA_ID,PUBLISHER_ID FROM CA_HAS_PUBLISHER";

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      rs = stmt.executeQuery();

      while (rs.next()) {
        int caId = rs.getInt("CA_ID");
        int publisherId = rs.getInt("PUBLISHER_ID");
        List<String> publisherNames = ret.computeIfAbsent(caId,
            k -> new LinkedList<>());
        publisherNames.add(publisherIdToNameMap.get(publisherId));
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    return ret;
  }

  private Map<Integer, List<String>> getCaHasProfiles(
      List<CaConfType.NameTypeConf> profiles)
      throws DataAccessException {
    Map<Integer, String> profileIdToNameMap = idToNameMap(profiles);

    Map<Integer, List<String>> ret = new HashMap<>();

    String sql = "SELECT CA_ID,PROFILE_ID";
    if (dbSchemaVersion > 8) {
      sql += ",ALIASES";
    }
    sql += " FROM CA_HAS_PROFILE";

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      rs = stmt.executeQuery();

      while (rs.next()) {
        int caId = rs.getInt("CA_ID");
        int profileId = rs.getInt("PROFILE_ID");
        String profileNameAndAliases = profileIdToNameMap.get(profileId);
        if (dbSchemaVersion > 8) {
          String aliases = rs.getString("ALIASES");
          profileNameAndAliases += ":" + aliases;
        }

        List<String> set = ret.computeIfAbsent(caId, k -> new LinkedList<>());
        set.add(profileNameAndAliases);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    return ret;
  }

  private Map<Integer, List<CaConfType.CaHasRequestor>> getCaHasRequestors(
      List<CaConfType.Requestor> requestors) throws DataAccessException {
    Map<Integer, String> requestorIdToNameMap = idToNameMap(requestors);
    Map<Integer, List<CaConfType.CaHasRequestor>> ret = new HashMap<>();

    final String sql = "SELECT CA_ID,REQUESTOR_ID,PERMISSION,PROFILES " +
        "FROM CA_HAS_REQUESTOR";

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      rs = stmt.executeQuery();

      while (rs.next()) {
        int caId = rs.getInt("CA_ID");
        int requestorId = rs.getInt("REQUESTOR_ID");
        int permission = rs.getInt("PERMISSION");
        String profiles = rs.getString("PROFILES");

        CaConfType.CaHasRequestor m = new CaConfType.CaHasRequestor(
            requestorIdToNameMap.get(requestorId),
            permissionToStringList(permission),
            StringUtil.split(profiles, ","));

        List<CaConfType.CaHasRequestor> set = ret.computeIfAbsent(caId,
            k -> new LinkedList<>());
        set.add(m);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    return ret;
  }

  private static Map<Integer, String> idToNameMap(
      List<? extends CaConfType.IdNameConf> entries) {
    Map<Integer, String> ret = new HashMap<>();
    for (CaConfType.IdNameConf m : entries) {
      ret.put(m.getId(), m.getName());
    }
    return ret;
  }

  private Permissions permissionToStringList(int permissionn) {
    if (dbSchemaVersion < 7) {
      permissionn |= PermissionConstants.GET_CERT;
    }
    return new Permissions(permissionn);
  }

}
