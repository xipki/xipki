// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.xipki.ca.api.mgmt.CaConfType;
import org.xipki.ca.api.mgmt.CaJson;
import org.xipki.ca.api.mgmt.CaProfileEntry;
import org.xipki.ca.api.mgmt.entry.CaConfColumn;
import org.xipki.ca.mgmt.db.DbSchemaInfo;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.PermissionConstants;
import org.xipki.util.SqlUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Database importer of CA configuration.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class CaconfDbImporter extends DbPorter {

  private final CaConfType.CaSystem caconf;

  CaconfDbImporter(DataSourceWrapper datasource, String srcDir, AtomicBoolean stopMe)
      throws DataAccessException, IOException, InvalidConfException {
    super(datasource, srcDir, stopMe);
    caconf = CaJson.parseObject(Paths.get(baseDir, FILENAME_CA_CONFIGURATION), CaConfType.CaSystem.class);
    caconf.validate();
  }

  public CaConfType.CaSystem getCaConf() {
    return caconf;
  }

  public void importToDb() throws Exception {
    System.out.println("importing CA configuration to database");
    try {
      importDbSchema(caconf.getDbSchemas());
      importSigner(caconf.getSigners());
      importRequestor(caconf.getRequestors());
      importPublisher(caconf.getPublishers());
      importProfile(caconf.getProfiles());
      importKeypairGen(caconf.getKeypairGens());

      List<CaConfType.Ca> cas = caconf.getCas();
      importCa(cas);
      importCaalias(cas);
      importCaHasRequestor(caconf);
      importCaHasPublisher(caconf);
      importCaHasCertprofile(caconf);
    } catch (Exception ex) {
      System.err.println("could not import CA configuration to database. message: " + ex.getMessage());
      throw ex;
    }
    System.out.println(" imported CA configuration to database");
  } // method importToDb

  private void importDbSchema(Map<String, String> entries) throws DataAccessException {
    System.out.print("    importing table DBSCHEMA ... ");

    if (entries == null) {
      System.out.println("nothing to import");
      return;
    }

    DbSchemaInfo dbSchemaInfo = new DbSchemaInfo(datasource);
    Set<String> dbSchemaNames = dbSchemaInfo.getVariableNames();

    final String sql = SqlUtil.buildInsertSql("DBSCHEMA", "NAME,VALUE2");
    PreparedStatement ps = null;

    boolean succ = false;
    try {
      ps = prepareStatement(sql);

      for (Map.Entry<String, String> entry : entries.entrySet()) {
        String name = entry.getKey();
        if (dbSchemaNames.contains(name)) {
          // do not import existing entry (with the same name)
          continue;
        }

        try {
          ps.setString(1, name);
          ps.setString(2, entry.getValue());

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import DBSCHEMA with NAME=" + name);
          throw translate(sql, ex);
        }
      }
      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importDbSchema

  private void importSigner(List<CaConfType.Signer> signers) throws DataAccessException, IOException {
    System.out.print("    importing table SIGNER ... ");
    if (signers == null) {
      System.out.println("nothing to import");
      return;
    }
    final String sql = SqlUtil.buildInsertSql("SIGNER", "NAME,TYPE,CERT,CONF");

    boolean succ = false;
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (CaConfType.Signer signer : signers) {
        String b64Cert = (signer.getCert() == null) ? null : Base64.encodeToString(readContent(signer.getCert()));
        try {
          int idx = 1;
          ps.setString(idx++, signer.getName());
          ps.setString(idx++, signer.getType());
          ps.setString(idx++, b64Cert);
          ps.setString(idx, readContent(signer.getConf()));

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import SIGNER with NAME=" + signer.getName());
          throw translate(sql, ex);
        }
      }

      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importSigner

  private void importRequestor(List<CaConfType.Requestor> requestors)
      throws DataAccessException, IOException {
    System.out.print("    importing table REQUESTOR ... ");
    final String sql = SqlUtil.buildInsertSql("REQUESTOR", "ID,NAME,TYPE,CONF");
    boolean succ = false;
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (CaConfType.Requestor requestor : requestors) {
        try {
          ps.setInt(1, requestor.getId());
          ps.setString(2, requestor.getName());
          ps.setString(3, requestor.getType());
          ps.setString(4, readContent(requestor.getConf()));

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import REQUESTOR with NAME=" + requestor.getName());
          throw translate(sql, ex);
        }
      }

      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importRequestor

  private void importPublisher(List<CaConfType.NameTypeConf> publishers)
      throws DataAccessException, IOException {
    System.out.print("    importing table PUBLISHER ... ");
    boolean succ = false;
    final String sql = SqlUtil.buildInsertSql("PUBLISHER", "ID,NAME,TYPE,CONF");
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      for (CaConfType.NameTypeConf publisher : publishers) {
        try {
          int idx = 1;
          ps.setInt(idx++, publisher.getId());
          ps.setString(idx++, publisher.getName());
          ps.setString(idx++, publisher.getType());
          ps.setString(idx, readContent(publisher.getConf()));

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import PUBLISHER with NAME=" + publisher.getName());
          throw translate(sql, ex);
        }
      }
      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importPublisher

  private void importProfile(List<CaConfType.NameTypeConf> profiles)
      throws DataAccessException, IOException {
    System.out.print("    importing table PROFILE ... ");
    boolean succ = false;
    final String sql = SqlUtil.buildInsertSql("PROFILE", "ID,NAME,TYPE,CONF");
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      for (CaConfType.NameTypeConf certprofile : profiles) {
        try {
          int idx = 1;
          ps.setInt(idx++, certprofile.getId());
          ps.setString(idx++, certprofile.getName());
          ps.setString(idx++, certprofile.getType());
          ps.setString(idx, readContent(certprofile.getConf()));

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import PROFILE with NAME=" + certprofile.getName());
          throw translate(sql, ex);
        } catch (IOException ex) {
          System.err.println("could not import PROFILE with NAME=" + certprofile.getName());
          throw ex;
        }
      }
      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importProfile

  private void importKeypairGen(List<CaConfType.NameTypeConf> keypairGens)
      throws DataAccessException, IOException {
    System.out.print("    importing table KEYPAIR_GEN ... ");
    if (keypairGens == null) {
      System.out.println("nothing to import");
      return;
    }

    boolean succ = false;
    final String deleteSql = "DELETE FROM KEYPAIR_GEN WHERE NAME=?";
    final String sql = SqlUtil.buildInsertSql("KEYPAIR_GEN", "NAME,TYPE,CONF");

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(deleteSql);
      for (CaConfType.NameTypeConf entry : keypairGens) {
        String name = entry.getName();
        try {
          ps.setString(1, name);
          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not delete KEYPAIR_GEN with NAME=" + name);
          throw translate(deleteSql, ex);
        }
      }
    } finally {
        releaseResources(ps, null);
    }

    ps = null;
    try {
      ps = prepareStatement(sql);

      for (CaConfType.NameTypeConf entry : keypairGens) {
        String name = entry.getName();
        try {
          ps.setString(1, entry.getName());
          ps.setString(2, entry.getType());
          ps.setString(3, readContent(entry.getConf()));

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import KEYPAIR_GEN with NAME=" + name);
          throw translate(sql, ex);
        }
      }

      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importKeypairGen

  private void importCa(List<CaConfType.Ca> cas)
      throws DataAccessException, CertificateException, IOException, InvalidConfException {
    System.out.print("    importing table CA ... ");
    boolean succ = false;

    final String sql = SqlUtil.buildInsertSql("CA",
        "ID,NAME,STATUS,NEXT_CRLNO,CRL_SIGNER_NAME,SUBJECT,REV_INFO,SIGNER_TYPE,SIGNER_CONF,CERT,CERTCHAIN,CONF");

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (CaConfType.Ca ca : cas) {
        CaConfType.CaInfo caInfo = ca.getCaInfo();

        try {
          byte[] certBytes = readContent(caInfo.getCert());
          X509Cert cert = X509Util.parseCert(certBytes);

          String certchainStr = null;
          if (caInfo.getCertchain() != null) {
            byte[][] certchainBytes = new byte[caInfo.getCertchain().size()][];
            for (int i = 0; i < certchainBytes.length; i++) {
              certchainBytes[i] = readContent(caInfo.getCertchain().get(i));
            }
            certchainStr = X509Util.encodeCertificates(certchainBytes);
          }

          String revInfoStr = null;
          if (caInfo.getRevocationInfo() != null) {
            revInfoStr = caInfo.getRevocationInfo().encode();
          }

          int idx = 1;
          ps.setInt(   idx++, ca.getId());
          ps.setString(idx++, ca.getName().toLowerCase());
          ps.setString(idx++, ca.getCaInfo().getStatus().getStatus());
          ps.setLong(  idx++, caInfo.getNextCrlNo());
          ps.setString(idx++, caInfo.getCrlSignerName());
          ps.setString(idx++, X509Util.cutX500Name(cert.getSubject(), maxX500nameLen));
          ps.setString(idx++, revInfoStr);
          ps.setString(idx++, caInfo.getSignerType());
          ps.setString(idx++, readContent(caInfo.getSignerConf()));
          ps.setString(idx++, Base64.encodeToString(certBytes));
          ps.setString(idx++, certchainStr);

          CaConfColumn caConfColumn = CaConfColumn.fromCaInfo(ca.getCaInfo());
          ps.setString(idx,   caConfColumn.encode());

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import CA with NAME=" + ca.getName());
          throw translate(sql, ex);
        } catch (CertificateException | IOException | InvalidConfException ex) {
          System.err.println("could not import CA with NAME=" + ca.getName());
          throw ex;
        }
      }

      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importCa

  private void importCaalias(List<CaConfType.Ca> cas) throws DataAccessException {
    System.out.print("    importing table CAALIAS ... ");

    boolean succ = false;
    final String sql = SqlUtil.buildInsertSql("CAALIAS", "NAME,CA_ID");
    PreparedStatement ps = prepareStatement(sql);
    try {
      for (CaConfType.Ca ca : cas) {
        for (String alias : ca.getAliases()) {
          try {
              ps.setString(1, alias);
              ps.setInt(2, ca.getId());
              ps.executeUpdate();
          } catch (SQLException ex) {
            System.err.println("could not import CAALIAS with alias=" + alias + " for CA " + ca.getName());
            throw translate(sql, ex);
          }
        }
      }
      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importCaalias

  private void importCaHasRequestor(CaConfType.CaSystem root)
      throws DataAccessException, InvalidConfException {
    System.out.print("    importing table CA_HAS_REQUESTOR ... ");
    boolean succ = false;
    final String sql = SqlUtil.buildInsertSql("CA_HAS_REQUESTOR", "CA_ID,REQUESTOR_ID,PERMISSION,PROFILES");
    PreparedStatement ps = prepareStatement(sql);
    try {
      Map<String, Integer> requestorNameToIdMap = nameToIdMap(root.getRequestors());

      for (CaConfType.Ca ca : root.getCas()) {
        for (CaConfType.CaHasRequestor entry : ca.getRequestors()) {
          String errMsg = "could not import CA_HAS_REQUESTOR for CA="
              + ca.getName() + " and REQUESTOR=" + entry.getRequestorName();
          try {
            int idx = 1;
            ps.setInt(idx++, ca.getId());
            ps.setInt(idx++, requestorNameToIdMap.get(entry.getRequestorName()));
            ps.setInt(idx++, PermissionConstants.toIntPermission(entry.getPermissions()));
            ps.setString(idx, StringUtil.collectionAsString(entry.getProfiles(), ",")); // TODO

            ps.executeUpdate();
          } catch (SQLException ex) {
            System.err.println(errMsg);
            throw translate(sql, ex);
          } catch (InvalidConfException ex) {
            System.err.println(errMsg);
            throw ex;
          }
        }
      }
      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importCaHasRequestor

  private void importCaHasPublisher(CaConfType.CaSystem root) throws Exception {
    System.out.print("    importing table CA_HAS_PUBLISHER ... ");
    boolean succ = false;
    final String sql = SqlUtil.buildInsertSql("CA_HAS_PUBLISHER", "CA_ID,PUBLISHER_ID");
    PreparedStatement ps = prepareStatement(sql);
    try {
      Map<String, Integer> publisherNameToIdMap = nameToIdMap(root.getPublishers());

      for (CaConfType.Ca ca : root.getCas()) {
        for (String publisher : ca.getPublishers()) {
          try {
            ps.setInt(1, ca.getId());
            ps.setInt(2, publisherNameToIdMap.get(publisher));

            ps.executeUpdate();
          } catch (SQLException ex) {
            System.err.println("could not import CA_HAS_PUBLISHER with CA=" + ca.getName()
                + " and PUBLISHER=" + publisher);
            throw translate(sql, ex);
          }
        }
      }
      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importCaHasPublisher

  private void importCaHasCertprofile(CaConfType.CaSystem root) throws DataAccessException {
    System.out.print("    importing table CA_HAS_PROFILE ... ");
    boolean succ = false;
    String columns = "CA_ID,PROFILE_ID";
    if (dbSchemaVersion > 8) {
      columns += ",ALIASES";
    }

    final String sql = SqlUtil.buildInsertSql("CA_HAS_PROFILE", columns);
    PreparedStatement ps = prepareStatement(sql);
    try {
      Map<String, Integer> profileNameToIdMap = nameToIdMap(root.getProfiles());

      for (CaConfType.Ca ca : root.getCas()) {
        for (String combinedProfile : ca.getProfiles()) {
          try {
            CaProfileEntry entry = CaProfileEntry.decode(combinedProfile);
            ps.setInt(1, ca.getId());

            ps.setInt(2, profileNameToIdMap.get((entry.getProfileName())));
            if (dbSchemaVersion > 8) {
              ps.setString(3, StringUtil.collectionAsString(entry.getProfileAliases(), ","));
            }

            ps.executeUpdate();
          } catch (SQLException ex) {
            System.err.println("could not import CA_HAS_PROFILE with CA="
                + ca.getName() + " and PROFILE=" + combinedProfile);
            throw translate(sql, ex);
          }
        }
      }
      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importCaHasCertprofile

  private static Map<String, Integer> nameToIdMap(List<? extends CaConfType.IdNameConf> entries) {
    Map<String, Integer> map = new HashMap<>();
    for (CaConfType.IdNameConf entry : entries) {
      map.put(entry.getName(), entry.getId());
    }
    return map;
  }

}
