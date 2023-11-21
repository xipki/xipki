// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.mgmt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.mgmt.*;
import org.xipki.ca.api.mgmt.CaConfType.NameTypeConf;
import org.xipki.ca.api.mgmt.entry.*;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.util.Base64;
import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.xipki.ca.server.CaUtil.*;

/**
 * Load / export CA configuration.
 *
 * @author Lijun Liao (xipki)
 */

class ConfLoader {

  private static final Logger LOG = LoggerFactory.getLogger(ConfLoader.class);

 private final CaManagerImpl manager;

  ConfLoader(CaManagerImpl manager) {
    this.manager = Args.notNull(manager, "manager");
  } // constructor

  void loadConf(InputStream zippedConfStream) throws CaMgmtException {
    manager.assertMasterModeAndSetuped();

    Args.notNull(zippedConfStream, "zippedConfStream");

    SecurityFactory securityFactory = manager.securityFactory;

    CaConf conf;
    try {
      conf = new CaConf(zippedConfStream, securityFactory);
    } catch (IOException | InvalidConfException ex) {
      throw new CaMgmtException("could not parse the CA configuration", ex);
    } catch (RuntimeException ex) {
      throw new CaMgmtException("caught RuntimeException while parsing the CA configuration", ex);
    }

    // DBSCHEMA
    for (String dbSchemaName : conf.getDbSchemaNames()) {
      manager.addDbSchema(dbSchemaName, conf.getDbSchema(dbSchemaName));
    }

    // KeypairGen
    for (String name : conf.getKeypairGenNames()) {
      KeypairGenEntry entry = conf.getKeypairGen(name);
      KeypairGenEntry entryB = manager.keypairGenDbEntries.get(name);
      if (entryB != null) {
        if (entry.equals(entryB)) {
          LOG.info("ignore existed keypairGen {}", name);
          continue;
        } else {
          throw logAndCreateException("keypairGen " + name + " existed, could not re-added it");
        }
      }

      try {
        manager.addKeypairGen(entry);
        LOG.info("added keypairGen {}", name);
      } catch (CaMgmtException ex) {
        String msg = "could not add keypairGen " + name;
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // Signer
    for (String name : conf.getSignerNames()) {
      SignerEntry entry = conf.getSigner(name);
      SignerEntry entryB = manager.signerDbEntries.get(name);
      if (entryB != null) {
        if (entry.equals(entryB)) {
          LOG.info("ignore existed signer {}", name);
          continue;
        } else {
          throw logAndCreateException("signer " + name + " existed, could not re-added it");
        }
      }

      try {
        manager.addSigner(entry);
        LOG.info("added signer {}", name);
      } catch (CaMgmtException ex) {
        String msg = "could not add signer " + name;
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    final boolean ignoreId = true;
    // Requestor
    for (String name : conf.getRequestorNames()) {
      RequestorEntry entry = conf.getRequestor(name);
      RequestorEntry entryB = manager.getRequestor(name);
      if (entryB != null) {
        if (entry.equals(entryB, ignoreId)) {
          LOG.info("ignore existed cert-based requestor {}", name);
          continue;
        } else {
          throw logAndCreateException("cert-based requestor " + name + " existed, could not re-added it");
        }
      }

      try {
        manager.addRequestor(entry);
        LOG.info("added cert-based requestor {}", name);
      } catch (CaMgmtException ex) {
        String msg = "could not add cert-based requestor " + name;
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // Publisher
    for (String name : conf.getPublisherNames()) {
      PublisherEntry entry = conf.getPublisher(name);
      PublisherEntry entryB = manager.getPublisher(name);
      if (entryB != null) {
        if (entry.equals(entryB, ignoreId)) {
          LOG.info("ignore existed publisher {}", name);
          continue;
        } else {
          throw logAndCreateException("publisher " + name + " existed, could not re-added it");
        }
      }

      try {
        manager.addPublisher(entry);
        LOG.info("added publisher {}", name);
      } catch (CaMgmtException ex) {
        String msg = "could not add publisher " + name;
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // Certprofile
    for (String name : conf.getCertprofileNames()) {
      CertprofileEntry entry = conf.getCertprofile(name);
      CertprofileEntry entryB = manager.getCertprofile(name);
      if (entryB != null) {
        if (entry.equals(entryB, ignoreId)) {
          LOG.info("ignore existed certprofile {}", name);
          continue;
        } else {
          throw logAndCreateException("certprofile " + name + " existed, could not re-added it");
        }
      }

      try {
        manager.addCertprofile(entry);
        LOG.info("added certprofile {}", name);
      } catch (CaMgmtException ex) {
        String msg = "could not add certprofile " + name;
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // CA
    for (String caName : conf.getCaNames()) {
      CaConf.SingleCa scc = conf.getCa(caName);

      CaConf.GenSelfIssued genSelfIssued = scc.getGenSelfIssued();
      CaEntry caEntry = scc.getCaEntry();
      if (caEntry != null) {
        if (manager.caInfos.containsKey(caName)) {
          CaEntry entryB = manager.caInfos.get(caName).getCaEntry();
          if (caEntry.getCert() == null && genSelfIssued != null) {
            SignerConf signerConf = new SignerConf(caEntry.getSignerConf());
            try (ConcurrentContentSigner signer
                     = securityFactory.createSigner(caEntry.getSignerType(), signerConf, (X509Cert) null)) {
              caEntry.setCert(signer.getCertificate());
            } catch (IOException | ObjectCreationException ex) {
              throw new CaMgmtException("could not create signer for CA " + caName, ex);
            }
          }

          if (caEntry.equals(entryB, true, true)) {
            LOG.info("ignore existing CA {}", caName);
          } else {
            throw logAndCreateException("CA " + caName + " existed, could not re-added it");
          }
        } else {
          if (genSelfIssued != null) {
            manager.generateRootCa(caEntry, genSelfIssued.getProfile(), genSelfIssued.getSubject(),
                genSelfIssued.getSerialNumber(), genSelfIssued.getNotBefore(), genSelfIssued.getNotAfter());
            LOG.info("generated root CA {}", caName);
          } else {
            try {
              manager.addCa(caEntry);
              LOG.info("added CA {}", caName);
            } catch (CaMgmtException ex) {
              String msg = "could not add CA " + caName;
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      }

      if (scc.getAliases() != null) {
        Set<String> aliasesB = manager.getAliasesForCa(caName);
        for (String aliasName : scc.getAliases()) {
          if (aliasesB != null && aliasesB.contains(aliasName)) {
            LOG.info("ignored adding existing CA alias {} to CA {}", aliasName, caName);
          } else {
            try {
              manager.addCaAlias(aliasName, caName);
              LOG.info("associated alias {} to CA {}", aliasName, caName);
            } catch (CaMgmtException ex) {
              String msg = "could not associate alias " + aliasName + " to CA " + caName;
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      }

      if (scc.getProfileNames() != null) {
        for (String profileName : scc.getProfileNames()) {
          try {
            manager.addCertprofileToCa(profileName, caName);
            LOG.info("added certprofile {} to CA {}", profileName, caName);
          } catch (CaMgmtException ex) {
            String msg = "could not add certprofile " + profileName + " to CA " + caName;
            LogUtil.error(LOG, ex, msg);
            throw new CaMgmtException(msg);
          }
        }
      }

      if (scc.getPublisherNames() != null) {
        Set<String> publishersB = manager.caHasPublishers.get(caName);
        for (String publisherName : scc.getPublisherNames()) {
          if (publishersB != null && publishersB.contains(publisherName)) {
            LOG.info("ignored adding publisher {} to CA {}", publisherName, caName);
          } else {
            try {
              manager.addPublisherToCa(publisherName, caName);
              LOG.info("added publisher {} to CA {}", publisherName, caName);
            } catch (CaMgmtException ex) {
              String msg = "could not add publisher " + publisherName + " to CA " + caName;
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      }

      if (scc.getRequestors() != null) {
        Set<CaHasRequestorEntry> requestorsB = manager.caHasRequestors.get(caName);

        for (CaHasRequestorEntry requestor : scc.getRequestors()) {
          String requestorName = requestor.getRequestorIdent().getName();
          CaHasRequestorEntry requestorB = null;
          if (requestorsB != null) {
            for (CaHasRequestorEntry m : requestorsB) {
              if (m.getRequestorIdent().getName().equals(requestorName)) {
                requestorB = m;
                break;
              }
            }
          }

          if (requestorB != null) {
            if (requestor.equals(requestorB, ignoreId)) {
              LOG.info("ignored adding requestor {} to CA {}", requestorName, caName);
            } else {
              throw logAndCreateException("could not add requestor " + requestorName + " to CA" + caName);
            }
          } else {
            try {
              manager.addRequestorToCa(requestor, caName);
              LOG.info("added publisher {} to CA {}", requestorName, caName);
            } catch (CaMgmtException ex) {
              String msg = "could not add requestor " + requestorName + " to CA " + caName;
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      } // scc.getRequestors()
    } // cas
  } // method loadConf

  InputStream exportConf(List<String> caNames) throws CaMgmtException, IOException {
    manager.assertMasterModeAndSetuped();

    if (caNames != null) {
      List<String> tmpCaNames = new ArrayList<>(caNames.size());
      for (String name : caNames) {
        name = name.toLowerCase();
        if (manager.x509cas.containsKey(name)) {
          tmpCaNames.add(name);
        }
      }
      caNames = tmpCaNames;
    } else {
      caNames = new ArrayList<>(manager.x509cas.keySet());
    }

    ByteArrayOutputStream bytesStream = new ByteArrayOutputStream(1048576); // initial 1M

    CaConfType.CaSystem root = new CaConfType.CaSystem();

    try (ZipOutputStream zipStream = new ZipOutputStream(bytesStream)) {
      zipStream.setLevel(Deflater.BEST_SPEED);

      // DBSchema
      root.setDbSchemas(manager.getDbSchemas());

      // cas
      if (CollectionUtil.isNotEmpty(caNames)) {
        List<CaConfType.Ca> list = new LinkedList<>();

        for (String name : manager.x509cas.keySet()) {
          if (!caNames.contains(name)) {
            continue;
          }

          CaConfType.Ca ca = new CaConfType.Ca();
          ca.setName(name);

          Set<String> strs = manager.getAliasesForCa(name);
          if (CollectionUtil.isNotEmpty(strs)) {
            ca.setAliases(new ArrayList<>(strs));
          }

          // CaHasRequestors
          Set<CaHasRequestorEntry> requestors = manager.caHasRequestors.get(name);
          if (CollectionUtil.isNotEmpty(requestors)) {
            ca.setRequestors(new ArrayList<>());

            for (CaHasRequestorEntry m : requestors) {
              String requestorName = m.getRequestorIdent().getName();

              CaConfType.CaHasRequestor chr = new CaConfType.CaHasRequestor();
              chr.setRequestorName(requestorName);
              chr.setProfiles(new ArrayList<>(m.getProfiles()));
              chr.setPermissions(m.getPermissions());

              ca.getRequestors().add(chr);
            }
          }

          Set<CaProfileEntry> caPofileEntries = manager.caHasProfiles.get(name);
          if (CollectionUtil.isNotEmpty(caPofileEntries)) {
            List<String> profileNameAndAliasesList = new ArrayList<>(caPofileEntries.size());
            for (CaProfileEntry entry : caPofileEntries) {
              profileNameAndAliasesList.add(entry.getEncoded());
            }
            Collections.sort(profileNameAndAliasesList);
            ca.setProfiles(profileNameAndAliasesList);
          }

          strs = manager.caHasPublishers.get(name);
          if (CollectionUtil.isNotEmpty(strs)) {
            ca.setPublishers(new ArrayList<>(strs));
          }

          CaConfType.CaInfo caInfoType = new CaConfType.CaInfo();
          ca.setCaInfo(caInfoType);

          CaEntry entry = manager.x509cas.get(name).getCaInfo().getCaEntry();
          entry.copyBaseInfoTo(caInfoType);

          // Certificate
          byte[] certBytes = entry.getCert().getEncoded();
          caInfoType.setCert(createFileOrBinary(zipStream, certBytes, "files/ca-" + name + "-cert.der"));

          // certchain
          List<X509Cert> certchain = entry.getCertchain();
          if (CollectionUtil.isNotEmpty(certchain)) {
            List<FileOrBinary> ccList = new LinkedList<>();

            for (int i = 0; i < certchain.size(); i++) {
              certBytes = certchain.get(i).getEncoded();
              ccList.add(createFileOrBinary(zipStream, certBytes, "files/ca-" + name + "-certchain-" + i + ".der"));
            }
            caInfoType.setCertchain(ccList);
          }

          caInfoType.setPermissions(entry.getPermissions());

          caInfoType.setSignerConf(createFileOrValue(zipStream, entry.getSignerConf(),
              "files/ca-" + name + "-signerconf.conf"));

          list.add(ca);
        }

        if (!list.isEmpty()) {
          root.setCas(list);
        }
      }

      // requestors
      if (CollectionUtil.isNotEmpty(manager.requestorDbEntries)) {
        List<CaConfType.Requestor> list = new LinkedList<>();

        for (String name : manager.requestorDbEntries.keySet()) {
          RequestorEntry entry = manager.requestorDbEntries.get(name);
          CaConfType.Requestor type = new CaConfType.Requestor();
          type.setName(name);
          type.setType(entry.getType());

          if (RequestorEntry.TYPE_CERT.equalsIgnoreCase(entry.getType())) {
            FileOrBinary fob = createFileOrBinary(zipStream,
                Base64.decode(entry.getConf()), "files/requestor-" + name + ".der");
            type.setBinaryConf(fob);
          } else {
            FileOrValue fov = createFileOrValue(zipStream,  entry.getConf(), "files/requestor-" + name + ".conf");
            type.setConf(fov);
          }

          list.add(type);
        }

        if (!list.isEmpty()) {
          root.setRequestors(list);
        }
      }

      // publishers
      if (CollectionUtil.isNotEmpty(manager.publisherDbEntries)) {
        List<NameTypeConf> list = new LinkedList<>();

        for (String name : manager.publisherDbEntries.keySet()) {
          PublisherEntry entry = manager.publisherDbEntries.get(name);
          NameTypeConf conf = new NameTypeConf();
          conf.setName(name);
          conf.setType(entry.getType());
          conf.setConf(createFileOrValue(zipStream, entry.getConf(), "files/publisher-" + name + ".conf"));
          list.add(conf);
        }

        if (!list.isEmpty()) {
          root.setPublishers(list);
        }
      }

      // profiles
      if (CollectionUtil.isNotEmpty(manager.certprofileDbEntries)) {
        List<NameTypeConf> list = new LinkedList<>();
        for (String name : manager.certprofileDbEntries.keySet()) {
          CertprofileEntry entry = manager.certprofileDbEntries.get(name);
          NameTypeConf conf = new NameTypeConf();
          conf.setName(name);
          conf.setType(entry.getType());
          conf.setConf(createFileOrValue(zipStream, entry.getConf(), "files/certprofile-" + name + ".conf"));
          list.add(conf);
        }

        if (!list.isEmpty()) {
          root.setProfiles(list);
        }
      }

      // signers
      if (CollectionUtil.isNotEmpty(manager.signerDbEntries)) {
        List<CaConfType.Signer> list = new LinkedList<>();

        for (String name : manager.signerDbEntries.keySet()) {
          SignerEntry entry = manager.signerDbEntries.get(name);
          CaConfType.Signer conf = new CaConfType.Signer();
          conf.setName(name);
          conf.setType(entry.getType());
          conf.setConf(createFileOrValue(zipStream, entry.getConf(), "files/signer-" + name + ".conf"));
          conf.setCert(createFileOrBase64Value(zipStream, entry.base64Cert(), "files/signer-" + name + ".der"));

          list.add(conf);
        }

        if (!list.isEmpty()) {
          root.setSigners(list);
        }
      }

      if (CollectionUtil.isNotEmpty(manager.keypairGenDbEntries)) {
        List<CaConfType.NameTypeConf> list = new LinkedList<>();

        for (String name : manager.keypairGenDbEntries.keySet()) {
          KeypairGenEntry entry = manager.keypairGenDbEntries.get(name);
          CaConfType.NameTypeConf conf = new CaConfType.NameTypeConf();
          conf.setName(name);
          conf.setType(entry.getType());
          if (entry.getConf() != null) {
            FileOrValue fv = new FileOrValue();
            fv.setValue(entry.getConf());
            conf.setConf(fv);
          }

          list.add(conf);
        }

        if (!list.isEmpty()) {
          root.setKeypairGens(list);
        }
      }

      // add the CAConf json file
      try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
        root.validate();
        CaJson.writePrettyJSON(root, bout);

        zipStream.putNextEntry(new ZipEntry("caconf.json"));
        try {
          zipStream.write(bout.toByteArray());
        } finally {
          zipStream.closeEntry();
        }
      } catch (InvalidConfException ex) {
        LogUtil.error(LOG, ex, "could not marshal CAConf");
        throw new CaMgmtException("could not marshal CAConf: " + ex.getMessage(), ex);
      }
    }

    return new ByteArrayInputStream(bytesStream.toByteArray());
  } // method exportConf

  private static CaMgmtException logAndCreateException(String msg) {
    LOG.error(msg);
    return new CaMgmtException(msg);
  }

}
