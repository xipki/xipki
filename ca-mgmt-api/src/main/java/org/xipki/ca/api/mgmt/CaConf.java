// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.entry.*;
import org.xipki.ca.api.mgmt.entry.CaEntry.CaSignerConf;
import org.xipki.security.*;
import org.xipki.security.util.JSON;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.*;
import java.util.Map.Entry;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * CA configuration.
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 */

public class CaConf {

  public static class GenSelfIssued {

    private final String profile;

    private final String subject;

    private final String serialNumber;

    private final Instant notBefore;

    private final Instant notAfter;

    public GenSelfIssued(String profile, String subject, String serialNumber, Instant notBefore, Instant notAfter) {
      this.profile = Args.notBlank(profile, "profile");
      this.subject = Args.notBlank(subject, "subject");
      this.serialNumber = serialNumber;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
    }

    public String getProfile() {
      return profile;
    }

    public String getSubject() {
      return subject;
    }

    public String getSerialNumber() {
      return serialNumber;
    }

    public Instant getNotBefore() {
      return notBefore;
    }

    public Instant getNotAfter() {
      return notAfter;
    }
  } // class GenSelfIssued

  public static class SingleCa {

    private final String name;

    private final GenSelfIssued genSelfIssued;

    private final CaEntry caEntry;

    private final List<String> aliases;

    private final List<String> profileNames;

    private final List<CaHasRequestorEntry> requestors;

    private final List<String> publisherNames;

    public SingleCa(
        String name, GenSelfIssued genSelfIssued, CaEntry caEntry, List<String> aliases,
        List<String> profileNames, List<CaHasRequestorEntry> requestors, List<String> publisherNames) {
      this.name = Args.notBlank(name, "name");
      if (genSelfIssued != null) {
        if (caEntry == null) {
          throw new IllegalArgumentException("caEntry may not be null if genSelfIssued is non-null");
        }

        if ((caEntry).getCert() != null) {
          throw new IllegalArgumentException("caEntry.cert may not be null if genSelfIssued is non-null");
        }
      }

      this.genSelfIssued = genSelfIssued;
      this.caEntry = caEntry;
      this.aliases = aliases;
      this.profileNames = profileNames;
      this.requestors = requestors;
      this.publisherNames = publisherNames;
    } // constructor

    public String getName() {
      return name;
    }

    public CaEntry getCaEntry() {
      return caEntry;
    }

    public List<String> getAliases() {
      return aliases;
    }

    public GenSelfIssued getGenSelfIssued() {
      return genSelfIssued;
    }

    public List<String> getProfileNames() {
      return profileNames;
    }

    public List<CaHasRequestorEntry> getRequestors() {
      return requestors;
    }

    public List<String> getPublisherNames() {
      return publisherNames;
    }

  } // class SingleCa

  private static final Logger LOG = LoggerFactory.getLogger(CaConf.class);

  private final Map<String, String> properties = new HashMap<>();

  private final Map<String, String> dbSchemas = new HashMap<>();

  private final Map<String, SignerEntry> signers = new HashMap<>();

  private final Map<String, RequestorEntry> requestors = new HashMap<>();

  private final Map<String, PublisherEntry> publishers = new HashMap<>();

  private final Map<String, CertprofileEntry> certprofiles = new HashMap<>();

  private final Map<String, KeypairGenEntry> keypairgens = new HashMap<>();

  private final Map<String, SingleCa> cas = new HashMap<>();

  public CaConf(File confFile, SecurityFactory securityFactory)
      throws IOException, InvalidConfException, CaMgmtException {
    Args.notNull(securityFactory, "securityFactory");
    confFile = IoUtil.expandFilepath(Args.notNull(confFile, "confFile"), true);

    init(Files.newInputStream(confFile.toPath()), securityFactory);
  }

  /**
   * The specified stream is closed after this method call.
   */
  public CaConf(InputStream confFileZipStream, SecurityFactory securityFactory)
      throws IOException, InvalidConfException, CaMgmtException {
    Args.notNull(confFileZipStream, "confFileZipStream");
    Args.notNull(securityFactory, "securityFactory");
    init(confFileZipStream, securityFactory);
  }

  private void init(InputStream zipFileStream, SecurityFactory securityFactory)
      throws IOException, InvalidConfException, CaMgmtException {
    ZipInputStream zipStream = new ZipInputStream(zipFileStream);

    try {
      Map<String, byte[]> zipEntries = new HashMap<>();

      ZipEntry zipEntry;
      while ((zipEntry = zipStream.getNextEntry()) != null) {
        byte[] zipEntryBytes = read(zipStream);
        zipEntries.put(zipEntry.getName(), zipEntryBytes);
      }

      CaConfType.CaSystem root = JSON.parseObject(zipEntries.get("caconf.json"), CaConfType.CaSystem.class);
      root.validate();
      init0(root, zipEntries, securityFactory);
    } finally {
      try {
        zipFileStream.close();
      } catch (IOException ex) {
        LOG.info("could not close zipFileStream: {}", ex.getMessage());
      }

      try {
        zipStream.close();
      } catch (IOException ex) {
        LOG.info("could not close zipStream: {}", ex.getMessage());
      }
    }
  } // method init

  private void init0(CaConfType.CaSystem root, Map<String, byte[]> zipEntries, SecurityFactory securityFactory)
      throws IOException, InvalidConfException, CaMgmtException {
    if (root.getProperties() != null) {
      properties.putAll(root.getProperties());
    }

    if (root.getDbSchemas() != null) {
      dbSchemas.putAll(root.getDbSchemas());
    }

    // Signers
    if (root.getSigners() != null) {
      for (CaConfType.Signer m : root.getSigners()) {
        SignerEntry en = new SignerEntry(m.getName(), expandConf(m.getType()),
            getValue(m.getConf(), zipEntries), getBase64Binary(m.getCert(), zipEntries));
        addSigner(en);
      }
    }

    // Requestors
    if (root.getRequestors() != null) {
      for (CaConfType.Requestor m : root.getRequestors()) {
        String conf;
        if (m.getConf() != null) {
          conf = getValue(m.getConf(), zipEntries);
        } else {
          conf = getBase64Binary(m.getBinaryConf(), zipEntries);
        }

        RequestorEntry en = new RequestorEntry(new NameId(null, m.getName()), m.getType(), conf);
        addRequestor(en);
      }
    }

    // Publishers
    if (root.getPublishers() != null) {
      for (CaConfType.NameTypeConf m : root.getPublishers()) {
        PublisherEntry en = new PublisherEntry(new NameId(null, m.getName()),
            expandConf(m.getType()), getValue(m.getConf(), zipEntries));
        addPublisher(en);
      }
    }

    // Profiles
    if (root.getProfiles() != null) {
      for (CaConfType.NameTypeConf m : root.getProfiles()) {
        CertprofileEntry en = new CertprofileEntry(new NameId(null, m.getName()),
            expandConf(m.getType()), getValue(m.getConf(), zipEntries));
        addProfile(en);
      }
    }

    // KeypairGens
    if (root.getKeypairGens() != null) {
      for (CaConfType.NameTypeConf m : root.getKeypairGens()) {
        KeypairGenEntry en = new KeypairGenEntry(m.getName(), m.getType(), getValue(m.getConf(), zipEntries));
        addKeypairGen(en);
      }
    }

    // CAs
    if (root.getCas() != null) {
      for (CaConfType.Ca m : root.getCas()) {
        String name = m.getName();
        GenSelfIssued genSelfIssued = null;
        CaEntry caEntry = null;

        if (m.getCaInfo() != null) {
          CaConfType.CaInfo ci = m.getCaInfo();
          CaConfType.GenSelfIssued gsi = ci.getGenSelfIssued();
          if (gsi != null) {
            if (ci.getCert() != null) {
              throw new InvalidConfException("cert.file of CA " + name + " may not be set");
            }

            Instant notBefore = gsi.getNotBefore() == null ? null
                : DateUtil.parseUtcTimeyyyyMMddhhmmss(gsi.getNotBefore());
            Instant notAfter = gsi.getNotAfter() == null ? null
                : DateUtil.parseUtcTimeyyyyMMddhhmmss(gsi.getNotAfter());
            genSelfIssued = new GenSelfIssued(gsi.getProfile(), gsi.getSubject(), gsi.getSerialNumber(),
                notBefore, notAfter);
          }

          CaUris caUris;
          if (ci.getCaUris() == null) {
            caUris = CaUris.EMPTY_INSTANCE;
          } else {
            CaConfType.CaUris uris = ci.getCaUris();
            caUris = new CaUris(uris.getCacertUris(), uris.getOcspUris(), uris.getCrlUris(), uris.getDeltaCrlUris());
          }

          int exprirationPeriod = (ci.getExpirationPeriod() == null) ? 365 : ci.getExpirationPeriod();

          int numCrls = (ci.getNumCrls() == null) ? 30 : ci.getNumCrls();

          caEntry = new CaEntry(new NameId(null, name), ci.getSnSize(), ci.getNextCrlNo(),
              expandConf(ci.getSignerType()), getValue(ci.getSignerConf(), zipEntries), caUris,
              numCrls, exprirationPeriod);

          if (ci.getCrlControl() != null) {
            caEntry.setCrlControl(new CrlControl(new ConfPairs(ci.getCrlControl()).getEncoded()));
          }

          if (ci.getCtlogControl() != null) {
            caEntry.setCtlogControl(new CtlogControl(new ConfPairs(ci.getCtlogControl()).getEncoded()));
          }

          caEntry.setCrlSignerName(ci.getCrlSignerName());
          caEntry.setKeypairGenNames(ci.getKeypairGenNames());

          if (ci.getExtraControl() != null) {
            caEntry.setExtraControl(new ConfPairs(ci.getExtraControl()).unmodifiable());
          }

          int keepExpiredCertDays = (ci.getKeepExpiredCertDays() == null) ? -1 : ci.getKeepExpiredCertDays();
          caEntry.setKeepExpiredCertInDays(keepExpiredCertDays);

          caEntry.setMaxValidity(Validity.getInstance(ci.getMaxValidity()));
          caEntry.setPermission(getIntPermission(ci.getPermissions()));

          if (ci.getRevokeSuspendedControl() != null) {
            caEntry.setRevokeSuspendedControl(
                new RevokeSuspendedControl(new ConfPairs(ci.getRevokeSuspendedControl())));
          }

          caEntry.setSaveCert(ci.isSaveCert());
          caEntry.setSaveKeypair(ci.isSaveKeypair());
          caEntry.setStatus(CaStatus.forName(ci.getStatus()));

          if (ci.getValidityMode() != null) {
            caEntry.setValidityMode(ValidityMode.forName(ci.getValidityMode()));
          }

          if (ci.getGenSelfIssued() == null) {
            X509Cert caCert;

            if (ci.getCert() != null) {
              byte[] bytes = getBinary(ci.getCert(), zipEntries);
              try {
                caCert = X509Util.parseCert(bytes);
              } catch (CertificateException ex) {
                throw new InvalidConfException("invalid certificate of CA " + name, ex);
              }
            } else {
              // extract from the signer configuration
              try {
                List<CaSignerConf> signerConfs = CaEntry.splitCaSignerConfs(getValue(ci.getSignerConf(), zipEntries));
                SignerConf signerConf = new SignerConf(signerConfs.get(0).getConf());

                try (ConcurrentContentSigner signer = securityFactory.createSigner(
                    expandConf(ci.getSignerType()), signerConf, (X509Cert) null)) {
                  caCert = signer.getCertificate();
                }
              } catch (IOException | ObjectCreationException | XiSecurityException ex) {
                throw new InvalidConfException("could not create CA signer for CA " + name, ex);
              }
            }

            caEntry.setCert(caCert);

            // certchain
            if (CollectionUtil.isNotEmpty(ci.getCertchain())) {
              List<X509Cert> certchain = new LinkedList<>();
              for (FileOrBinary cc : ci.getCertchain()) {
                byte[] bytes = getBinary(cc, zipEntries);
                try {
                  certchain.add(X509Util.parseCert(bytes));
                } catch (CertificateException ex) {
                  throw new InvalidConfException("invalid certchain for CA " + name, ex);
                }
              }

              caEntry.setCertchain(certchain);
            }
          }
        }

        List<CaHasRequestorEntry> caHasRequestors = null;
        if (m.getRequestors() != null) {
          caHasRequestors = new LinkedList<>();
          for (CaConfType.CaHasRequestor req : m.getRequestors()) {
            CaHasRequestorEntry en = new CaHasRequestorEntry(new NameId(null, req.getRequestorName()));

            if (req.getProfiles() != null && !req.getProfiles().isEmpty()) {
              en.setProfiles(new HashSet<>(req.getProfiles()));
            }

            en.setPermission(getIntPermission(req.getPermissions()));
            caHasRequestors.add(en);
          }
        }

        List<String> aliases = null;
        if (m.getAliases() != null && !m.getAliases().isEmpty()) {
          aliases = m.getAliases();
        }
        List<String> profileNames = null;
        if (m.getProfiles() != null && !m.getProfiles().isEmpty()) {
          profileNames = m.getProfiles();
        }

        List<String> publisherNames = null;
        if (m.getPublishers() != null && !m.getPublishers().isEmpty()) {
          publisherNames = m.getPublishers();
        }

        SingleCa singleCa = new SingleCa(name, genSelfIssued, caEntry, aliases,
            profileNames, caHasRequestors, publisherNames);
        addSingleCa(singleCa);
      }
    }

  } // method init0

  public void addSigner(SignerEntry signer) {
    Args.notNull(signer, "signer");
    this.signers.put(signer.getName(), signer);
  }

  public Set<String> getSignerNames() {
    return Collections.unmodifiableSet(signers.keySet());
  }

  public SignerEntry getSigner(String name) {
    return signers.get(Args.notNull(name, "name"));
  }

  public void addRequestor(RequestorEntry requestor) {
    Args.notNull(requestor, "requestor");
    this.requestors.put(requestor.getIdent().getName(), requestor);
  }

  public Set<String> getRequestorNames() {
    return Collections.unmodifiableSet(requestors.keySet());
  }

  public RequestorEntry getRequestor(String name) {
    return requestors.get(Args.notNull(name, "name"));
  }

  public void addPublisher(PublisherEntry publisher) {
    Args.notNull(publisher, "publisher");
    this.publishers.put(publisher.getIdent().getName(), publisher);
  }

  public Set<String> getPublisherNames() {
    return Collections.unmodifiableSet(publishers.keySet());
  }

  public PublisherEntry getPublisher(String name) {
    return publishers.get(Args.notNull(name, "name"));
  }

  public void addProfile(CertprofileEntry profile) {
    Args.notNull(profile, "profile");
    this.certprofiles.put(profile.getIdent().getName(), profile);
  }

  public Set<String> getCertprofileNames() {
    return Collections.unmodifiableSet(certprofiles.keySet());
  }

  public CertprofileEntry getCertprofile(String name) {
    return certprofiles.get(Args.notNull(name, "name"));
  }

  public void addKeypairGen(KeypairGenEntry keypairgen) {
    Args.notNull(keypairgen, "keypairgen");
    this.keypairgens.put(keypairgen.getName(), keypairgen);
  }

  public Set<String> getKeypairGenNames() {
    return Collections.unmodifiableSet(keypairgens.keySet());
  }

  public KeypairGenEntry getKeypairGen(String name) {
    return keypairgens.get(Args.notNull(name, "name"));
  }

  public void addSingleCa(SingleCa singleCa) {
    Args.notNull(singleCa, "singleCa");
    this.cas.put(singleCa.getName(), singleCa);
  }

  public Set<String> getDbSchemaNames() {
    return Collections.unmodifiableSet(dbSchemas.keySet());
  }

  public String getDbSchema(String name) {
    return dbSchemas.get(name);
  }

  public Set<String> getCaNames() {
    return Collections.unmodifiableSet(cas.keySet());
  }

  public SingleCa getCa(String name) {
    return cas.get(Args.notNull(name, "name"));
  }

  private String getValue(FileOrValue fileOrValue, Map<String, byte[]> zipEntries)
      throws IOException {
    if (fileOrValue == null) {
      return null;
    }

    if (fileOrValue.getValue() != null) {
      return expandConf(fileOrValue.getValue());
    }

    String fileName = fileOrValue.getFile();
    byte[] binary = zipEntries.get(fileName);
    if (binary == null) {
      throw new IOException("could not find ZIP entry " + fileName);
    }

    return expandConf(StringUtil.toUtf8String(binary));
  } // method getValue

  private String getBase64Binary(FileOrBinary fileOrBinary, Map<String, byte[]> zipEntries)
      throws IOException {
    byte[] binary = getBinary(fileOrBinary, zipEntries);
    return (binary == null) ? null : Base64.encodeToString(binary);
  }

  private static byte[] read(InputStream in) throws IOException {
    try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
      int readed;
      byte[] buffer = new byte[2048];
      while ((readed = in.read(buffer)) != -1) {
        bout.write(buffer, 0, readed);
      }

      return bout.toByteArray();
    }
  } // method read

  private byte[] getBinary(FileOrBinary fileOrBinary, Map<String, byte[]> zipEntries)
      throws IOException {
    if (fileOrBinary == null) {
      return null;
    }

    if (fileOrBinary.getBinary() != null) {
      return fileOrBinary.getBinary();
    }

    String fileName = fileOrBinary.getFile();
    byte[] binary = zipEntries.get(fileName);
    if (binary == null) {
      throw new IOException("could not find ZIP entry " + fileName);
    }

    return binary;
  } //method getBinary

  private String expandConf(String confStr) {
    if (confStr == null || !confStr.contains("${") || confStr.indexOf('}') == -1) {
      return confStr;
    }

    for (Entry<String, String> entry : properties.entrySet()) {
      String name = entry.getKey();
      String placeHolder = "${" + name + "}";
      while (confStr.contains(placeHolder)) {
        confStr = confStr.replace(placeHolder, entry.getValue());
      }
    }

    return confStr;
  } // method expandConf

  private static int getIntPermission(List<String> permissions)
      throws InvalidConfException {
    int ret = 0;
    for (String permission : permissions) {
      Integer ii = PermissionConstants.getPermissionForText(permission);
      if (ii == null) {
        throw new InvalidConfException("invalid permission " + permission);
      }
      ret |= ii;
    }
    return ret;
  } // method getIntPermission

}
