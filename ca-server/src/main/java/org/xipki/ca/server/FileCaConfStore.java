// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.*;
import org.xipki.ca.api.mgmt.entry.*;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.CertprofileFactoryRegister;
import org.xipki.ca.server.db.CertStore;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.mgmt.CaProfileIdAliases;
import org.xipki.ca.server.mgmt.SelfSignedCertBuilder;
import org.xipki.password.PasswordResolver;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;
import org.xipki.util.exception.OperationException;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.*;

/**
 * This class represents the file-based CA configuration.
 * @author Lijun Liao (xipki)
 */
public class FileCaConfStore implements CaConfStore {

  private static final Logger LOG = LoggerFactory.getLogger(FileCaConfStore.class);

  private static final CaMgmtException readOnlyException = new CaMgmtException("File based CaConfStore is read-only");

  private static final int REQUESTOR_BY_CA_ID = 1;

  private final Map<String, String> dbSchemas;

  private final int dbSchemaversion = 9;

  private final List<String> caNames;

  private final List<String> keyPairGenNames;

  private final List<String> profileNames;

  private final List<String> publisherNames;

  private final List<String> requestorNames;

  private final List<String> signerNames;

  private final Map<String, CaEntry> caTable = new HashMap<>();

  private final Map<String, CertprofileEntry> certprofileTable = new HashMap<>();

  private final Map<String, PublisherEntry> publisherTable = new HashMap<>();

  private final Map<String, RequestorEntry> requestorTable = new HashMap<>();

  private final Map<String, SignerEntry> signerTable = new HashMap<>();

  private final Map<String, KeypairGenEntry> keypairGenTable = new HashMap<>();

  private final Map<String, Integer> requestorNameToIdMap;

  private final Map<String, Set<CaHasRequestorEntry>> caHasRequestors;

  private final Map<String, Set<CaProfileIdAliases>> caHasProfiles;

  private final Map<String, Set<Integer>> caHasPublisherIds;

  private final Map<String, String> aliasToCaNames;

  private final Map<String, Integer> aliasToCaIds;

  private final boolean needsCertStore;

  public FileCaConfStore(SecurityFactory securityFactory,
                         CertprofileFactoryRegister certprofileFactoryRegister,
                         List<String> confFiles)
      throws IOException, CaMgmtException, InvalidConfException {
    if (confFiles == null || confFiles.isEmpty()) {
      throw new IllegalArgumentException("confFile shall not be empty");
    }

    String baseDir = null;
    for (String confFile : confFiles) {
      File fileobj = new File(IoUtil.expandFilepath(confFile, true));
      if (baseDir == null) {
        baseDir = fileobj.getParent();
      } else {
        if (!CompareUtil.equalsObject(baseDir, fileobj.getParent())) {
          throw new IllegalArgumentException("Not all confFiles have the same parent dir");
        }
      }
    }

    if (baseDir == null) {
      baseDir = ".";
    }

    CaConfType.CaSystem root = mergeConfs(confFiles);

    //-- make sure all names, IDs are unique
    Map<String, Integer> profileNameIdMap = assertNameIdUnique(root.getProfiles(), "profile");
    profileNames = List.copyOf(profileNameIdMap.keySet());

    Map<String, Integer> publisherNameIdMap = assertNameIdUnique(root.getPublishers(), "publisher");
    publisherNames = List.copyOf(publisherNameIdMap.keySet());

    signerNames = Collections.unmodifiableList(assertNameUnique(root.getSigners(), "signer"));

    Map<String, Integer> requestorNameIdMap = assertNameIdUnique(root.getRequestors(), "requestor");
    if (requestorNameIdMap.containsKey(RequestorInfo.NAME_BY_CA)) {
      throw new InvalidConfException(
          "requestor name " + RequestorInfo.NAME_BY_CA + " is reserved and shall no be used");
    }
    requestorNameIdMap.put(RequestorInfo.NAME_BY_CA, REQUESTOR_BY_CA_ID);

    this.requestorNames = List.copyOf(requestorNameIdMap.keySet());
    this.requestorNameToIdMap = Collections.unmodifiableMap(requestorNameIdMap);

    keyPairGenNames = Collections.unmodifiableList(assertNameUnique(root.getKeypairGens(), "keypairGen"));

    Map<String, Integer> caNameIdMap = assertNameIdUnique(root.getCas(), "CA");
    caNames = List.copyOf(caNameIdMap.keySet());

    //-- make sure the requestor does not have reserved id
    for (CaConfType.Requestor m : root.getRequestors()) {
      if (m.getId() == REQUESTOR_BY_CA_ID) {
        throw new InvalidConfException("requestor id " + m.getId() + " is reserved and shall not be used");
      }
    }

    //-- make sure all referenced names (e.g. signer, requestor, publisher) are present.
    Map<String, Integer> caAliasNameIdMap = new HashMap<>();
    for (CaConfType.Ca ca : root.getCas()) {
      // aliases
      for (String alias : ca.getAliases()) {
        if (caAliasNameIdMap.containsKey(alias)) {
          throw new InvalidConfException("duplicated CA alias " + alias);
        }
        caAliasNameIdMap.put(alias, ca.getId());
      }

      // publisher
      for (String m : ca.getPublishers()) {
        if (!publisherNameIdMap.containsKey(m)) {
          throw new InvalidConfException("unknown publisher " + m);
        }
      }

      // requestor
      for (CaConfType.CaHasRequestor m : ca.getRequestors()) {
        if (!requestorNameIdMap.containsKey(m.getRequestorName())) {
          throw new InvalidConfException("unknown requestor " + m.getRequestorName());
        }
      }

      // profile
      Set<String> localProfileNames = new HashSet<>();
      for (String profile : ca.getProfiles()) {
        CaProfileEntry entry = CaProfileEntry.decode(profile);
        if (!profileNameIdMap.containsKey(entry.getProfileName())) {
          throw new InvalidConfException("unknown certprofile " + entry.getProfileName());
        }

        localProfileNames.add(entry.getProfileName());
        for (String alias : entry.getProfileAliases()) {
          if (localProfileNames.contains(alias)) {
            throw new InvalidConfException("duplicated cerprofile alias " + alias);
          }
          localProfileNames.add(alias);
        }
      }

      CaConfType.CaInfo caInfo = ca.getCaInfo();
      if (caInfo != null) {
        // CRL signner
        String tname = caInfo.getCrlSignerName();
        if (tname != null && !signerNames.contains(tname)) {
          throw new InvalidConfException("unknown signer " + tname);
        }

        if (caInfo.getKeypairGenNames() != null) {
          for (String m : caInfo.getKeypairGenNames()) {
            if (!keyPairGenNames.contains(m)) {
              throw new InvalidConfException("unknown keypairGen " + m);
            }
          }
        }
      }
    }

    //-- DB Schemas
    // add default db schemas if not set.
    if (!root.getDbSchemas().containsKey("VENDOR")) {
      root.getDbSchemas().put("VENDOR", "XIPKI");
    }

    if (!root.getDbSchemas().containsKey("X500NAME_MAXLEN")) {
      root.getDbSchemas().put("X500NAME_MAXLEN", "350");
    }

    if (!root.getDbSchemas().containsKey("VERSION")) {
      root.getDbSchemas().put("VERSION", "9");
    }

    this.dbSchemas = Collections.unmodifiableMap(root.getDbSchemas());

    // Signers
    for (CaConfType.Signer m : root.getSigners()) {
      String name = m.getName();
      try {
        SignerEntry entry = new SignerEntry(name, m.getType(),
            getValue(m.getConf(), baseDir), getBase64Value(m.getCert(), baseDir));
        signerTable.put(name, entry);
        LOG.info("initialized signer {}", name);
      } catch (Exception ex) {
        throw new InvalidConfException("error initializing signer " + name, ex);
      }
    }

    // Requestors
    for (CaConfType.Requestor m : root.getRequestors()) {
      NameId ident = new NameId(m.getId(), m.getName());
      try {
        String conf;
        if (m.getConf() != null) {
          conf = getValue(m.getConf(), baseDir);
        } else {
          if ("cert".equalsIgnoreCase(m.getType())) {
            byte[] binary = getBinary(m.getBinaryConf(), baseDir);
            if (binary == null) {
              conf = null;
            } else {
              binary = X509Util.toDerEncoded(binary);
              conf = Base64.encodeToString(binary);
            }
          } else {
            conf = getBase64Value(m.getBinaryConf(), baseDir);
          }
        }

        RequestorEntry entry = new RequestorEntry(ident, m.getType(), conf);
        requestorTable.put(ident.getName(), entry);
        LOG.info("initialized requestor {}", ident);
      } catch (Exception ex) {
        throw new InvalidConfException("error initializing requestor " + ident, ex);
      }
    }

    // Publishers
    for (CaConfType.NameTypeConf m : root.getPublishers()) {
      NameId ident = new NameId(m.getId(), m.getName());
      try {
        PublisherEntry entry = new PublisherEntry(ident, m.getType(), getValue(m.getConf(), baseDir));
        publisherTable.put(ident.getName(), entry);
        LOG.info("initialized publisher {}", ident);
      } catch (Exception ex) {
        throw new InvalidConfException("error initializing publisher " + ident, ex);
      }
    }

    // KeypairGen
    for (CaConfType.NameTypeConf m : root.getKeypairGens()) {
      String name = m.getName();
      try {
        KeypairGenEntry entry = new KeypairGenEntry(name, m.getType(), getValue(m.getConf(), baseDir));
        keypairGenTable.put(name, entry);
        LOG.info("initialized KeyPairGen {}", name);
      } catch (RuntimeException ex) {
        throw new InvalidConfException("error initializing KeyPairGen " + name, ex);
      }
    }

    // Profiles
    for (CaConfType.NameTypeConf m : root.getProfiles()) {
      NameId ident = new NameId(m.getId(), m.getName());
      try {
        CertprofileEntry entry = new CertprofileEntry(ident, m.getType(), getValue(m.getConf(), baseDir));
        certprofileTable.put(ident.getName(), entry);
        LOG.info("initialized certprofile {}", ident);
      } catch (RuntimeException ex) {
        throw new InvalidConfException("error initializing certprofile " + ident, ex);
      }
    }

    // CAs
    Map<String, String> caAliasToNameMap = new HashMap<>();
    Map<String, Set<String>> caHasPublisherMap = new HashMap<>();
    Map<String, Set<CaProfileIdAliases>> caHasProfileMap = new HashMap<>();
    Map<String, Set<CaHasRequestorEntry>> caHasRequestorMap = new HashMap<>();

    if (root.getCas() != null) {
      for (CaConfType.Ca m : root.getCas()) {
        String caName = m.getName();
        NameId ident = new NameId(m.getId(), caName);
        try {
          CaEntry entry = buildCaEntry(m, baseDir, certprofileFactoryRegister, securityFactory);
          caTable.put(caName, entry);
          LOG.info("initialized CA {}", ident);
        } catch (Exception ex) {
          throw new InvalidConfException("error initializing CA " + ident, ex);
        }

        // Alias
        if (m.getAliases() != null) {
          for (String alias : m.getAliases()) {
            caAliasToNameMap.put(alias, caName);
          }
        }

        // Publisher
        if (m.getPublishers() != null) {
           caHasPublisherMap.put(caName, new HashSet<>(m.getPublishers()));
        }

        // Certprofile
        if (m.getProfiles() != null) {
          Set<CaProfileIdAliases> set = new HashSet<>();
          for (String combinedProfile : m.getProfiles()) {
            try {
              CaProfileEntry entry0 = CaProfileEntry.decode(combinedProfile);
              String profileName = entry0.getProfileName();
              CertprofileEntry certprofileEntry = certprofileTable.get(profileName);
              CaProfileIdAliases entry = new CaProfileIdAliases(
                  certprofileEntry.getIdent().getId(), entry0.getEncodedAliases());
              set.add(entry);
            } catch (Exception ex) {
              throw new CaMgmtException("invalid syntax of CaProfileEntry '" + combinedProfile + "'", ex);
            }
          }
          caHasProfileMap.put(caName, set);
        }

        // Requestor
        if (m.getRequestors() != null) {
          Set<CaHasRequestorEntry> set = new HashSet<>();
          for (CaConfType.CaHasRequestor c : m.getRequestors()) {
            RequestorEntry entry0 = requestorTable.get(c.getRequestorName());
            CaHasRequestorEntry entry = new CaHasRequestorEntry(entry0.getIdent());
            entry.setPermission(PermissionConstants.toIntPermission(c.getPermissions()));
            entry.setProfiles(c.getProfiles() == null
                ? Collections.emptySet() : new HashSet<>(c.getProfiles()));
            set.add(entry);
          }
          caHasRequestorMap.put(caName, set);
        }

        CaConfType.CaInfo caInfo = m.getCaInfo();
        if (caInfo != null) {
          // KeyPairGen
        }
      }
    }

    this.caHasProfiles = Collections.unmodifiableMap(caHasProfileMap);
    this.caHasRequestors = Collections.unmodifiableMap(caHasRequestorMap);

    this.aliasToCaNames = Collections.unmodifiableMap(caAliasToNameMap);
    Map<String, Integer> map = new HashMap<>();
    for (Map.Entry<String, String> m : this.aliasToCaNames.entrySet()) {
      int caId = caNameIdMap.get(m.getValue());
      map.put(m.getKey(), caId);
    }
    this.aliasToCaIds = Collections.unmodifiableMap(map);

    Map<String, Set<Integer>> caHasPublisherIds = new HashMap<>();
    for (Map.Entry<String, Set<String>> m : caHasPublisherMap.entrySet()) {
      String caName = m.getKey();
      Set<Integer> ids = new HashSet<>();
      for (String publisheName : m.getValue()) {
        ids.add(publisherNameIdMap.get(publisheName));
      }
      caHasPublisherIds.put(caName, ids);
    }
    this.caHasPublisherIds = Collections.unmodifiableMap(caHasPublisherIds);

    boolean saveCertOrKey = false;
    for (CaConfType.Ca ca : root.getCas()) {
      if (ca.getCaInfo().isSaveCert() || ca.getCaInfo().isSaveKeypair()) {
        saveCertOrKey = true;
        break;
      }
    }

    this.needsCertStore = saveCertOrKey;
  }

  private CaEntry buildCaEntry(CaConfType.Ca ca, String baseDir,
                               CertprofileFactoryRegister certprofileFactoryRegister,
                               SecurityFactory securityFactory)
      throws InvalidConfException, IOException, CaMgmtException {
    NameId ident = new NameId(ca.getId(), ca.getName());
    CaConfType.CaInfo ci = ca.getCaInfo();

    if (ci.getGenSelfIssued() != null) {
      if (ci.getCert() != null) {
        throw new InvalidConfException("cert.file of CA " + ident + " may not be set");
      }

      // check if the certificate has been generated before.
      File certFile = new File(baseDir, "generated-rootcerts/" + ident.getName() + ".pem");
      X509Cert cert;
      if (certFile.exists()) {
        try {
          cert = X509Util.parseCert(certFile);
        } catch (CertificateException e) {
          throw new CaMgmtException("error parsing certificate " + certFile.getPath());
        }
      } else {
        CaConfType.GenSelfIssued gsi = ci.getGenSelfIssued();
        Instant notBefore = gsi.getNotBefore() == null ? null
            : DateUtil.parseUtcTimeyyyyMMddhhmmss(gsi.getNotBefore());
        Instant notAfter = gsi.getNotAfter() == null ? null
            : DateUtil.parseUtcTimeyyyyMMddhhmmss(gsi.getNotAfter());
        CaConf.GenSelfIssued genSelfIssued =
            new CaConf.GenSelfIssued(gsi.getProfile(), gsi.getSubject(), gsi.getSerialNumber(), notBefore, notAfter);

        IdentifiedCertprofile certprofile;
        try {
          CertprofileEntry certprofileConfEntry = certprofileTable.get(gsi.getProfile());
          Certprofile certprofile0 = certprofileFactoryRegister.newCertprofile(certprofileConfEntry.getType());
          certprofile0.initialize(certprofileConfEntry.getConf());
          certprofile = new IdentifiedCertprofile(certprofileConfEntry, certprofile0);
        } catch (ObjectCreationException | CertprofileException | RuntimeException ex) {
          throw new CaMgmtException("error initializing certprofile " + gsi.getProfile());
        }

        String signerConf = getValue(ci.getSignerConf(), baseDir);

        try {
          cert = SelfSignedCertBuilder.generateSelfSigned(securityFactory,
              ci.getSignerType(), signerConf, certprofile, genSelfIssued.getSubject(),
              genSelfIssued.getSerialNumber(), genSelfIssued.getNotBefore(), genSelfIssued.getNotAfter());
        } catch (OperationException ex) {
          throw new CaMgmtException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }

        // save the binary, and replace the configuration file.
        IoUtil.save(certFile, X509Util.toPemCert(cert).getBytes(StandardCharsets.UTF_8));
      }

      ci.setCert(FileOrBinary.ofBinary(cert.getEncoded()));
    }

    CaEntry caEntry = new CaEntry(ident);
    ci.copyBaseInfoTo(caEntry);

    caEntry.setPermission(PermissionConstants.toIntPermission(ci.getPermissions()));
    caEntry.setSignerConf(getValue(ci.getSignerConf(), baseDir));

    if (caEntry.getCaUris() == null) {
      caEntry.setCaUris(CaUris.EMPTY_INSTANCE);
    }

    if (ci.getCrlControl() != null) {
      caEntry.setCrlControl(new CrlControl(new ConfPairs(ci.getCrlControl()).getEncoded()));
    }

    if (ci.getCtlogControl() != null) {
      caEntry.setCtlogControl(new CtlogControl(new ConfPairs(ci.getCtlogControl()).getEncoded()));
    }

    if (ci.getExtraControl() != null) {
      caEntry.setExtraControl(new ConfPairs(ci.getExtraControl()).unmodifiable());
    }

    if (ci.getRevokeSuspendedControl() != null) {
      caEntry.setRevokeSuspendedControl(new RevokeSuspendedControl(new ConfPairs(ci.getRevokeSuspendedControl())));
    }

    X509Cert caCert;

    if (ci.getCert() != null) {
      byte[] bytes = getBinary(ci.getCert(), baseDir);
      try {
        caCert = X509Util.parseCert(bytes);
      } catch (CertificateException ex) {
        throw new InvalidConfException("invalid certificate of CA " + ident, ex);
      }
    } else {
      // extract from the signer configuration
      try {
        List<CaEntry.CaSignerConf> signerConfs = CaEntry.splitCaSignerConfs(getValue(ci.getSignerConf(), baseDir));
        SignerConf signerConf = new SignerConf(signerConfs.get(0).getConf());

        try (ConcurrentContentSigner signer = securityFactory.createSigner(
            ci.getSignerType(), signerConf, (X509Cert) null)) {
          caCert = signer.getCertificate();
        }
      } catch (IOException | ObjectCreationException | XiSecurityException ex) {
        throw new InvalidConfException("could not create CA signer for CA " + ident, ex);
      }
    }

    caEntry.setCert(caCert);

    // certchain
    if (CollectionUtil.isNotEmpty(ci.getCertchain())) {
      List<X509Cert> certchain = new LinkedList<>();
      for (FileOrBinary cc : ci.getCertchain()) {
        byte[] bytes = getBinary(cc, baseDir);
        try {
          certchain.add(X509Util.parseCert(bytes));
        } catch (CertificateException ex) {
          throw new InvalidConfException("invalid certchain for CA " + ident, ex);
        }
      }

      caEntry.setCertchain(certchain);
    }

    if (caEntry.getCrlControl() != null && !caEntry.isSaveCert()) {
      throw new InvalidConfException("crlCControl shall be null, since saveCert=true");
    }

    return caEntry;
  }

  private static String getValue(FileOrValue fv, String baseDir) throws IOException {
    if (fv == null) {
      return null;
    }
    if (fv.getValue() != null) {
      String value = fv.getValue();
      if (value.contains("${basedir}")) {
        value = value.replace("${basedir}", baseDir);
      }
      return value;
    }

    String expandedPath = IoUtil.expandFilepath(fv.getFile());
    Path path = Paths.get(expandedPath);
    if (!path.isAbsolute()) {
      path = Paths.get(baseDir, expandedPath);
    }

    return StringUtil.toUtf8String(Files.readAllBytes(path));
  }

  private static CaConfType.CaSystem mergeConfs(List<String> confFiles)
      throws IOException, InvalidConfException {
    CaConfType.CaSystem conf0 = CaJson.parseObject(
        Paths.get(IoUtil.expandFilepath(confFiles.get(0), true)), CaConfType.CaSystem.class);

    Map<String, String> dbSchemas = conf0.getDbSchemas();
    if (dbSchemas == null) {
      dbSchemas = new HashMap<>();
      conf0.setDbSchemas(dbSchemas);
    }

    List<CaConfType.NameTypeConf> profiles = conf0.getProfiles();
    if (profiles == null) {
      profiles = new LinkedList<>();
      conf0.setProfiles(profiles);
    }

    List<CaConfType.Requestor> requestors = conf0.getRequestors();
    if (requestors == null) {
      requestors = new LinkedList<>();
      conf0.setRequestors(requestors);
    }

    List<CaConfType.NameTypeConf> publishers = conf0.getPublishers();
    if (publishers == null) {
      publishers = new LinkedList<>();
      conf0.setPublishers(publishers);
    }

    List<CaConfType.Signer> signers = conf0.getSigners();
    if (signers == null) {
      signers = new LinkedList<>();
      conf0.setSigners(signers);
    }

    List<CaConfType.NameTypeConf> keypairGens = conf0.getKeypairGens();
    if (keypairGens == null) {
      keypairGens = new LinkedList<>();
      conf0.setKeypairGens(keypairGens);
    }

    List<CaConfType.Ca> cas = conf0.getCas();
    if (cas == null) {
      cas = new LinkedList<>();
      conf0.setCas(cas);
    }

    for (int i = 1; i < confFiles.size(); i++) {
      CaConfType.CaSystem root = CaJson.parseObject(
          Paths.get(IoUtil.expandFilepath(confFiles.get(i), true)), CaConfType.CaSystem.class);

      // Db Schemas
      if (root.getDbSchemas() != null) {
        for (Map.Entry<String, String> entry : root.getDbSchemas().entrySet()) {
          String name = entry.getKey();
          if (dbSchemas.containsKey(name)) {
            if (!CompareUtil.equalsObject(dbSchemas.get(name), entry.getValue())) {
              throw new InvalidConfException("Duplicated DbSchema '" + name + "' but with differnt values");
            }
          }
        }
      }

      // Requestors
      if (root.getRequestors() != null) {
        requestors.addAll(root.getRequestors());
      }

      // Publishers
      if (root.getPublishers() != null) {
        publishers.addAll(root.getPublishers());
      }

      // Cert-profiles
      if (root.getProfiles() != null) {
        profiles.addAll(root.getProfiles());
      }

      // KeypairGens
      if (root.getKeypairGens() != null) {
        keypairGens.addAll(root.getKeypairGens());
      }

      // Signers
      if (root.getSigners() != null) {
        signers.addAll(root.getSigners());
      }

      if (root.getCas() != null) {
        cas.addAll(root.getCas());
      }
    }

    boolean withSoftwareKeyPairGen = false;
    String nameSoftware = "software";
    for (CaConfType.NameTypeConf kg : keypairGens) {
      if (nameSoftware.equalsIgnoreCase(kg.getName())) {
        withSoftwareKeyPairGen = true;

        if (!"software".equalsIgnoreCase(kg.getType())) {
          throw new InvalidConfException("KeyPairGen name 'software' is reserved");
        }

        break;
      }
    }

    if (!withSoftwareKeyPairGen) {
      CaConfType.NameTypeConf sw = new CaConfType.NameTypeConf();
      sw.setName(nameSoftware);
      sw.setType("software");
      keypairGens.add(sw);
    }

    return conf0;
  }

  private static Map<String, Integer> assertNameIdUnique(List<? extends CaConfType.IdNameConf> list, String type)
      throws InvalidConfException {
    Map<String, Integer> nameIdMap = new HashMap<>();
    for (CaConfType.IdNameConf c : list) {
      String name = c.getName();
      if (nameIdMap.containsKey(name)) {
        throw new InvalidConfException("Duplicated name of " + type + " " + name);
      }

      Integer id = c.getId();
      if (id == null) {
        throw new InvalidConfException("id shall not be null");
      }

      if (id == 0) {
        throw new InvalidConfException("id value 0 is not allowed");
      }

      if (nameIdMap.containsValue(id)) {
        throw new InvalidConfException("Duplicated id of " + type + " " + name);
      }

      nameIdMap.put(name, id);
    }
    return nameIdMap;
  }

  private static List<String> assertNameUnique(
      List<? extends CaConfType.NameTypeConf> list, String type)
      throws InvalidConfException {
    List<String> names = new ArrayList<>(list.size());
    for (CaConfType.NameTypeConf c : list) {
      String name = c.getName();
      if (names.contains(name)) {
        throw new InvalidConfException("Duplicated name of " + type + " " + name);
      }
      names.add(name);
    }
    return names;
  }

  private static String getBase64Value(FileOrBinary fb, String baseDir) throws IOException {
    byte[] binary = getBinary(fb, baseDir);
    return binary == null ? null : Base64.encodeToString(binary);
  }

  private static byte[] getBinary(FileOrBinary fb, String baseDir) throws IOException {
    if (fb == null) {
      return null;
    }
    if (fb.getBinary() != null) {
      return fb.getBinary();
    }

    String expandedPath = IoUtil.expandFilepath(fb.getFile());
    Path path = Paths.get(expandedPath);
    if (!path.isAbsolute()) {
      path = Paths.get(baseDir, expandedPath);
    }

    return Files.readAllBytes(path);
  }

  @Override
  public boolean needsCertStore() {
    return needsCertStore;
  }

  @Override
  public SystemEvent getSystemEvent(String eventName) throws CaMgmtException {
    return null;
  }

  @Override
  public void changeSystemEvent(SystemEvent systemEvent) throws CaMgmtException {
    // do nothing
  }

  @Override
  public Map<String, Integer> createCaAliases() throws CaMgmtException {
    return aliasToCaIds;
  }

  @Override
  public CertprofileEntry createCertprofile(String name) throws CaMgmtException {
    return Optional.ofNullable(certprofileTable.get(name)).orElseThrow(
        () -> new CaMgmtException("Unknown Certprofile " + name));
  }

  @Override
  public PublisherEntry createPublisher(String name) throws CaMgmtException {
    return Optional.ofNullable(publisherTable.get(name)).orElseThrow(
        () -> new CaMgmtException("Unknown Publisher " + name));
  }

  @Override
  public Integer getRequestorId(String requestorName) throws CaMgmtException {
    return requestorNameToIdMap.get(requestorName);
  }

  @Override
  public RequestorEntry createRequestor(String name) throws CaMgmtException {
    return Optional.ofNullable(requestorTable.get(name)).orElseThrow(
        () -> new CaMgmtException("Unknown Requestor " + name));
  }

  @Override
  public SignerEntry createSigner(String name) throws CaMgmtException {
    return Optional.ofNullable(signerTable.get(name)).orElseThrow(
        () -> new CaMgmtException("Unknown Signer " + name));
  }

  @Override
  public KeypairGenEntry createKeypairGen(String name) throws CaMgmtException {
    return Optional.ofNullable(keypairGenTable.get(name)).orElseThrow(
        () -> new CaMgmtException("Unknown KeypairGen " + name));
  }

  @Override
  public CaInfo createCaInfo(String name, CertStore certstore) throws CaMgmtException {
    CaEntry caEntry = caTable.get(name);
    if (caEntry == null) {
      throw new CaMgmtException("unknown CA " + name);
    }

    try {
      return new CaInfo(caEntry, CaConfColumn.fromCaEntry(caEntry), certstore);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex);
    }
  }

  @Override
  public Set<CaHasRequestorEntry> createCaHasRequestors(NameId ca) throws CaMgmtException {
    return caHasRequestors.get(ca.getName());
  }

  @Override
  public Set<CaProfileIdAliases> createCaHasProfiles(NameId ca) throws CaMgmtException {
    return caHasProfiles.get(ca.getName());
  }

  @Override
  public Set<Integer> createCaHasPublishers(NameId ca) throws CaMgmtException {
    return caHasPublisherIds.get(ca.getName());
  }

  @Override
  public void addCa(CaEntry caEntry) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addCaAlias(String aliasName, NameId ca) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addCertprofile(CertprofileEntry dbEntry) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addCertprofileToCa(NameId profile, NameId ca, List<String> aliases) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addPublisherToCa(NameId publisher, NameId ca) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addRequestor(RequestorEntry dbEntry) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public NameId addEmbeddedRequestor(String requestorName) throws CaMgmtException {
    if (RequestorInfo.NAME_BY_CA.equals(requestorName)) {
      return new NameId(REQUESTOR_BY_CA_ID, RequestorInfo.NAME_BY_CA);
    }

    throw readOnlyException;
  }

  @Override
  public void addRequestorToCa(CaHasRequestorEntry requestor, NameId ca) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addPublisher(PublisherEntry dbEntry) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void changeCa(ChangeCaEntry changeCaEntry, CaConfColumn currentCaConfColumn,
                       SecurityFactory securityFactory) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void commitNextCrlNoIfLess(NameId ca, long nextCrlNo) throws CaMgmtException {
    // Not supported. Relies solely on the analysis of the CRLs saved in the database.
  }

  @Override
  public IdentifiedCertprofile changeCertprofile(
      NameId nameId, String type, String conf, CaManagerImpl certprofileManager) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public RequestorEntryWrapper changeRequestor(
      NameId nameId, String type, String conf, PasswordResolver passwordResolver) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public SignerEntry changeSigner(
      String name, String type, String conf, String base64Cert, CaManagerImpl signerManager) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public KeypairGenEntryWrapper changeKeypairGen(
      String name, String type, String conf, CaManagerImpl manager) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public IdentifiedCertPublisher changePublisher(
      String name, String type, String conf, CaManagerImpl publisherManager) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void removeCaAlias(String aliasName) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void removePublisherFromCa(String publisherName, String caName) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void removeDbSchema(String name) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addKeypairGen(KeypairGenEntry dbEntry) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addSigner(SignerEntry dbEntry) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void unlockCa() throws CaMgmtException {
  }

  @Override
  public void unrevokeCa(String caName) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public int getDbSchemaVersion() {
    return dbSchemaversion;
  }

  @Override
  public void addDbSchema(String name, String value) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void changeDbSchema(String name, String value) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public Map<String, String> getDbSchemas() throws CaMgmtException {
    return dbSchemas;
  }

  @Override
  public List<String> getCaNames() throws CaMgmtException {
    return caNames;
  }

  @Override
  public boolean deleteCa(String name) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public List<String> getKeyPairGenNames() throws CaMgmtException {
    return keyPairGenNames;
  }

  @Override
  public boolean deleteKeyPairGen(String name) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public List<String> getProfileNames() throws CaMgmtException {
    return profileNames;
  }

  @Override
  public boolean deleteProfile(String name) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public List<String> getPublisherNames() throws CaMgmtException {
    return publisherNames;
  }

  @Override
  public boolean deletePublisher(String name) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public List<String> getRequestorNames() throws CaMgmtException {
    return requestorNames;
  }

  @Override
  public boolean deleteRequestor(String name) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public List<String> getSignerNames() throws CaMgmtException {
    return signerNames;
  }

  @Override
  public boolean deleteSigner(String name) throws CaMgmtException {
    throw readOnlyException;
  }

}
