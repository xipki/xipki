// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CaEntry.CaSignerConf;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.security.SecurityFactory;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.security.sign.SignerConf;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.io.FileOrBinary;
import org.xipki.util.io.FileOrValue;
import org.xipki.util.misc.StringUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * CA configuration.
 *
 * @author Lijun Liao (xipki)
 */

public class CaConf {

  private static final Logger LOG = LoggerFactory.getLogger(CaConf.class);

  private final Map<String, String> dbSchemas = new HashMap<>();

  private final Map<String, SignerEntry> signers = new HashMap<>();

  private final Map<String, RequestorEntry> requestors = new HashMap<>();

  private final Map<String, PublisherEntry> publishers = new HashMap<>();

  private final Map<String, CertprofileEntry> certprofiles = new HashMap<>();

  private final Map<String, KeypairGenEntry> keypairgens = new HashMap<>();

  private final Map<String, SingleCa> cas = new HashMap<>();

  /**
   * Constructor from ZIP input stream.
   * The specified stream is closed after this method call.
   * @param confFileZipStream
   *        the input stream containing the zipped CA configuration.
   * @param securityFactory
   *        An {@link SecurityFactory} with helper methods.
   * @throws IOException if IO error occurs while reading the input stream.
   * @throws InvalidConfException if the CA configuration is not valid.
   * @throws CaMgmtException if other non-RuntimeException error occurs.
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

      byte[] bytes = zipEntries.get("caconf.json");
      if (LOG.isDebugEnabled()) {
        LOG.debug("ZIP.caconf.json: {}", StringUtil.toUtf8String(bytes));
      }
      JsonMap json = JsonParser.parseMap(bytes, true);
      CaConfType.CaSystem root = CaConfType.CaSystem.parse(json);
      init0(root, zipEntries, securityFactory);
    } catch (CodecException e) {
      throw new InvalidConfException("could not parse caconf.json", e);
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

  private void init0(CaConfType.CaSystem root, Map<String, byte[]> zipEntries,
                     SecurityFactory securityFactory)
      throws IOException, InvalidConfException, CaMgmtException {
    if (root.dbSchemas() != null) {
      dbSchemas.putAll(root.dbSchemas());
    }

    // Signers
    if (root.signers() != null) {
      for (CaConfType.Signer m : root.signers()) {
        SignerEntry en = new SignerEntry(m.name(), m.type(),
            getValue(m.conf(), zipEntries), getBase64Binary(m.cert(),
            zipEntries));
        addSigner(en);
      }
    }

    // Requestors
    if (root.requestors() != null) {
      for (CaConfType.Requestor m : root.requestors()) {
        String conf;
        if (m.conf() != null) {
          conf = getValue(m.conf(), zipEntries);
        } else {
          if ("cert".equalsIgnoreCase(m.type())) {
            byte[] binary = getBinary(m.binaryConf(), zipEntries);
            if (binary == null) {
              conf = null;
            } else {
              binary = X509Util.toDerEncoded(binary);
              conf = Base64.encodeToString(binary);
            }
          } else {
            conf = getBase64Binary(m.binaryConf(), zipEntries);
          }
        }

        RequestorEntry en = new RequestorEntry(new NameId(null, m.name()),
            m.type(), conf);
        addRequestor(en);
      }
    }

    // Publishers
    if (root.publishers() != null) {
      for (CaConfType.NameTypeConf m : root.publishers()) {
        PublisherEntry en = new PublisherEntry(new NameId(null, m.name()),
            m.type(), getValue(m.conf(), zipEntries));
        addPublisher(en);
      }
    }

    // Profiles
    if (root.profiles() != null) {
      for (CaConfType.NameTypeConf m : root.profiles()) {
        CertprofileEntry en = new CertprofileEntry(
            new NameId(null, m.name()), m.type(),
            getValue(m.conf(), zipEntries));
        addProfile(en);
      }
    }

    // KeypairGens
    if (root.keypairGens() != null) {
      for (CaConfType.NameTypeConf m : root.keypairGens()) {
        KeypairGenEntry en = new KeypairGenEntry(m.name(), m.type(),
            getValue(m.conf(), zipEntries));
        addKeypairGen(en);
      }
    }

    // CAs
    if (root.cas() != null) {
      for (CaConfType.Ca m : root.cas()) {
        String name = m.name();
        GenSelfIssued genSelfIssued = null;
        CaEntry caEntry = null;

        if (m.caInfo() != null) {
          CaConfType.CaInfo ci = m.caInfo();
          CaConfType.GenSelfIssued gsi = ci.genSelfIssued();
          if (gsi != null) {
            if (ci.cert() != null) {
              throw new InvalidConfException(
                  "cert.file of CA " + name + " may not be set");
            }

            Instant notBefore = gsi.notBefore() == null ? null
                : DateUtil.parseUtcTimeyyyyMMddhhmmss(gsi.notBefore());
            Instant notAfter = gsi.notAfter() == null ? null
                : DateUtil.parseUtcTimeyyyyMMddhhmmss(gsi.notAfter());
            genSelfIssued = new GenSelfIssued(gsi.profile(),
                gsi.subject(), gsi.serialNumber(), notBefore, notAfter);
          }

          caEntry = new CaEntry(ci.base(), new NameId(null, name),
              getValue(ci.signerConf(), zipEntries));

          if (ci.genSelfIssued() == null) {
            X509Cert caCert;

            if (ci.cert() != null) {
              byte[] bytes = getBinary(ci.cert(), zipEntries);
              try {
                caCert = X509Util.parseCert(bytes);
              } catch (CertificateException ex) {
                throw new InvalidConfException(
                    "invalid certificate of CA " + name, ex);
              }
            } else {
              // extract from the signer configuration
              try {
                List<CaSignerConf> signerConfs = CaEntry.splitCaSignerConfs(
                    getValue(ci.signerConf(), zipEntries));
                SignerConf signerConf =
                    new SignerConf(signerConfs.get(0).conf());

                String signerType = ci.base().signerType();
                ConcurrentSigner signer = securityFactory.createSigner(
                    signerType, signerConf, (X509Cert) null);
                try {
                  caCert = signer.getX509Cert();
                } finally {
                  signer.close();
                }
              } catch (IOException | ObjectCreationException
                       | XiSecurityException ex) {
                throw new InvalidConfException(
                    "could not create CA signer for CA " + name, ex);
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
                  throw new InvalidConfException(
                      "invalid certchain for CA " + name, ex);
                }
              }

              caEntry.setCertchain(certchain);
            }
          }
        }

        List<CaHasRequestorEntry> caHasRequestors = null;
        if (m.requestors() != null) {
          caHasRequestors = new LinkedList<>();
          for (CaConfType.CaHasRequestor req : m.requestors()) {
            CaHasRequestorEntry en = new CaHasRequestorEntry(
                new NameId(null, req.requestorName()),
                req.permissions(), req.profiles());
            caHasRequestors.add(en);
          }
        }

        List<String> aliases = null;
        if (m.aliases() != null && !m.aliases().isEmpty()) {
          aliases = m.aliases();
        }
        List<String> profileNames = null;
        if (m.profiles() != null && !m.profiles().isEmpty()) {
          profileNames = m.profiles();
        }

        List<String> publisherNames = null;
        if (m.publishers() != null && !m.publishers().isEmpty()) {
          publisherNames = m.publishers();
        }

        SingleCa singleCa = new SingleCa(name, genSelfIssued, caEntry, aliases,
            profileNames, caHasRequestors, publisherNames);
        addSingleCa(singleCa);
      }
    }

  } // method init0

  public void addSigner(SignerEntry signer) {
    Args.notNull(signer, "signer");
    this.signers.put(signer.name(), signer);
  }

  public Set<String> getSignerNames() {
    return Collections.unmodifiableSet(signers.keySet());
  }

  public SignerEntry getSigner(String name) {
    return signers.get(Args.notNull(name, "name"));
  }

  public void addRequestor(RequestorEntry requestor) {
    Args.notNull(requestor, "requestor");
    this.requestors.put(requestor.ident().name(), requestor);
  }

  public Set<String> getRequestorNames() {
    return Collections.unmodifiableSet(requestors.keySet());
  }

  public RequestorEntry getRequestor(String name) {
    return requestors.get(Args.notNull(name, "name"));
  }

  public void addPublisher(PublisherEntry publisher) {
    Args.notNull(publisher, "publisher");
    this.publishers.put(publisher.ident().name(), publisher);
  }

  public Set<String> getPublisherNames() {
    return Collections.unmodifiableSet(publishers.keySet());
  }

  public PublisherEntry getPublisher(String name) {
    return publishers.get(Args.notNull(name, "name"));
  }

  public void addProfile(CertprofileEntry profile) {
    Args.notNull(profile, "profile");
    this.certprofiles.put(profile.ident().name(), profile);
  }

  public Set<String> getCertprofileNames() {
    return Collections.unmodifiableSet(certprofiles.keySet());
  }

  public CertprofileEntry getCertprofile(String name) {
    return certprofiles.get(Args.notNull(name, "name"));
  }

  public void addKeypairGen(KeypairGenEntry keypairgen) {
    Args.notNull(keypairgen, "keypairgen");
    this.keypairgens.put(keypairgen.name(), keypairgen);
  }

  public Set<String> getKeypairGenNames() {
    return Collections.unmodifiableSet(keypairgens.keySet());
  }

  public KeypairGenEntry getKeypairGen(String name) {
    return keypairgens.get(Args.notNull(name, "name"));
  }

  public void addSingleCa(SingleCa singleCa) {
    Args.notNull(singleCa, "singleCa");
    this.cas.put(singleCa.name(), singleCa);
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

  private String getValue(FileOrValue fileOrValue,
                          Map<String, byte[]> zipEntries)
      throws IOException {
    if (fileOrValue == null) {
      return null;
    }

    if (fileOrValue.value() != null) {
      return fileOrValue.value();
    }

    String fileName = fileOrValue.file();
    byte[] binary = zipEntries.get(fileName);
    if (binary == null) {
      throw new IOException("could not find ZIP entry " + fileName);
    }

    return StringUtil.toUtf8String(binary);
  } // method getValue

  private String getBase64Binary(FileOrBinary fileOrBinary,
                                 Map<String, byte[]> zipEntries)
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

  private byte[] getBinary(FileOrBinary fileOrBinary,
                           Map<String, byte[]> zipEntries)
      throws IOException {
    if (fileOrBinary == null) {
      return null;
    }

    if (fileOrBinary.binary() != null) {
      return fileOrBinary.binary();
    }

    String fileName = fileOrBinary.file();
    byte[] binary = zipEntries.get(fileName);
    if (binary == null) {
      throw new IOException("could not find ZIP entry " + fileName);
    }

    return binary;
  } //method getBinary

  public static class GenSelfIssued {

    private final String profile;

    private final String subject;

    private final String serialNumber;

    private final Instant notBefore;

    private final Instant notAfter;

    public GenSelfIssued(String profile, String subject, String serialNumber,
                         Instant notBefore, Instant notAfter) {
      this.profile = Args.notBlank(profile, "profile");
      this.subject = Args.notBlank(subject, "subject");
      this.serialNumber = serialNumber;
      this.notBefore    = notBefore;
      this.notAfter     = notAfter;
    }

    public String profile() {
      return profile;
    }

    public String subject() {
      return subject;
    }

    public String serialNumber() {
      return serialNumber;
    }

    public Instant notBefore() {
      return notBefore;
    }

    public Instant notAfter() {
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

    public SingleCa(String name, GenSelfIssued genSelfIssued, CaEntry caEntry,
                    List<String> aliases, List<String> profileNames,
                    List<CaHasRequestorEntry> requestors,
                    List<String> publisherNames) {
      this.name = Args.notBlank(name, "name");
      if (genSelfIssued != null) {
        if (caEntry == null) {
          throw new IllegalArgumentException(
              "caEntry may not be null if genSelfIssued is non-null");
        }

        if ((caEntry).cert() != null) {
          throw new IllegalArgumentException(
              "caEntry.cert may not be null if genSelfIssued is non-null");
        }
      }

      this.genSelfIssued = genSelfIssued;
      this.caEntry = caEntry;
      this.aliases = aliases;
      this.profileNames = profileNames;
      this.requestors = requestors;
      this.publisherNames = publisherNames;
    } // constructor

    public String name() {
      return name;
    }

    public CaEntry caEntry() {
      return caEntry;
    }

    public List<String> aliases() {
      return aliases;
    }

    public GenSelfIssued genSelfIssued() {
      return genSelfIssued;
    }

    public List<String> profileNames() {
      return profileNames;
    }

    public List<CaHasRequestorEntry> requestors() {
      return requestors;
    }

    public List<String> publisherNames() {
      return publisherNames;
    }

  } // class SingleCa

}
