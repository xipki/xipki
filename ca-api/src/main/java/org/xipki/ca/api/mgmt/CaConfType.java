// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.ca.api.mgmt.entry.BaseCaInfo;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.VariableResolver;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.io.FileOrBinary;
import org.xipki.util.io.FileOrValue;
import org.xipki.util.misc.StringUtil;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * CA configuration types.
 *
 * @author Lijun Liao (xipki)
 */
public class CaConfType {

  private static void putNameTypeConfs(
      JsonMap map, String name, List<NameTypeConf> value) {
    if (value != null) {
      JsonList list = new JsonList();
      for (NameTypeConf v : value) {
        list.add(v.toCodec());
      }
      map.put(name, list);
    }
  }

  public static class CaSystem implements JsonEncodable {

    /**
     * Specify the base directory for relative path specified in this
     * configuration file. Use 'APP_DIR' for application working directory.
     * Default is the directory where this configuration file locates. Will be
     * ignored if this configuration file is contained in a ZIP file.
     */
    private String basedir;

    private Map<String, String> properties;

    private Map<String, String> dbSchemas;

    private List<Signer> signers;

    private List<Requestor> requestors;

    private List<NameTypeConf> publishers;

    private List<NameTypeConf> profiles;

    private List<NameTypeConf> keypairGens;

    private List<Ca> cas;

    public String basedir() {
      return basedir;
    }

    public void setBasedir(String basedir) {
      this.basedir = basedir;
    }

    public Map<String, String> dbSchemas() {
      if (dbSchemas == null) {
        dbSchemas = new HashMap<>();
      }
      return dbSchemas;
    }

    public Map<String, String> properties() {
      return properties;
    }

    public void setProperties(Map<String, String> properties) {
      this.properties = properties;
    }

    public void setDbSchemas(Map<String, String> dbSchemas) {
      this.dbSchemas = dbSchemas;
    }

    public List<Signer> signers() {
      if (signers == null) {
        signers = new LinkedList<>();
      }
      return signers;
    }

    public void setSigners(List<Signer> signers) {
      this.signers = signers;
    }

    public List<Requestor> requestors() {
      if (requestors == null) {
        requestors = new LinkedList<>();
      }
      return requestors;
    }

    public void setRequestors(List<Requestor> requestors) {
      this.requestors = requestors;
    }

    public List<NameTypeConf> publishers() {
      if (publishers == null) {
        publishers = new LinkedList<>();
      }
      return publishers;
    }

    public void setPublishers(List<NameTypeConf> publishers) {
      this.publishers = publishers;
    }

    public List<NameTypeConf> profiles() {
      if (profiles == null) {
        profiles = new LinkedList<>();
      }
      return profiles;
    }

    public void setProfiles(List<NameTypeConf> profiles) {
      this.profiles = profiles;
    }

    public List<NameTypeConf> keypairGens() {
      if (keypairGens == null) {
        keypairGens = new LinkedList<>();
      }
      return keypairGens;
    }

    public void setKeypairGens(List<NameTypeConf> keypairGens) {
      this.keypairGens = keypairGens;
    }

    public List<Ca> cas() {
      if (cas == null) {
        cas = new LinkedList<>();
      }
      return cas;
    }

    public void setCas(List<Ca> cas) {
      this.cas = cas;
    }

    public static CaSystem parse(Path path)
        throws InvalidConfException {
      try {
        return parse(JsonParser.parseMap(path, true));
      } catch (CodecException e) {
        throw new InvalidConfException(
            "error parsing CaSystem: " + e.getMessage(), e);
      }
    }

    public static CaSystem parse(JsonMap json) throws CodecException {
      Map<String, String> properties = json.getStringMap("properties");
      if (CollectionUtil.isNotEmpty(properties)) {
        json.setVariableResolver(
            new VariableResolver.MapVariableResolver(properties));
      }

      CaSystem ret = new CaSystem();

      ret.setBasedir(json.getString("basedir"));
      ret.setProperties(properties);
      ret.setDbSchemas(json.getStringMap("dbSchemas"));

      JsonList list = json.getList("signers");
      if (list != null) {
        List<Signer> signers = new ArrayList<>(list.size());
        ret.setSigners(signers);
        for (JsonMap m : list.toMapList()) {
          signers.add(Signer.parse(m));
        }
      }

      list = json.getList("requestors");
      if (list != null) {
        List<Requestor> requestors = new ArrayList<>(list.size());
        ret.setRequestors(requestors);
        for (JsonMap m : list.toMapList()) {
          requestors.add(Requestor.parse(m));
        }
      }

      list = json.getList("publishers");
      if (list != null) {
        List<NameTypeConf> publishers = new ArrayList<>(list.size());
        ret.setPublishers(publishers);
        for (JsonMap m : list.toMapList()) {
          publishers.add(NameTypeConf.parse(m));
        }
      }

      list = json.getList("profiles");
      if (list != null) {
        List<NameTypeConf> profiles = new ArrayList<>(list.size());
        ret.setProfiles(profiles);
        for (JsonMap m : list.toMapList()) {
          profiles.add(NameTypeConf.parse(m));
        }
      }

      list = json.getList("keypairGens");
      if (list != null) {
        List<NameTypeConf> keypairGens = new ArrayList<>(list.size());
        ret.setKeypairGens(keypairGens);
        for (JsonMap m : list.toMapList()) {
          keypairGens.add(NameTypeConf.parse(m));
        }
      }

      list = json.getList("cas");
      if (list != null) {
        List<Ca> cas = new ArrayList<>(list.size());
        ret.setCas(cas);
        for (JsonMap m : list.toMapList()) {
          cas.add(Ca.parse(m));
        }
      }

      return ret;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.putStringMap("properties", properties);
      ret.putStringMap("dbSchemas",  dbSchemas);

      if (signers != null) {
        JsonList list = new JsonList();
        ret.put("signers", list);
        for (Signer m : signers) {
          list.add(m.toCodec());
        }
      }

      if (requestors != null) {
        JsonList list = new JsonList();
        ret.put("requestors", list);
        for (Requestor m : requestors) {
          list.add(m.toCodec());
        }
      }

      putNameTypeConfs(ret, "publishers", publishers);
      putNameTypeConfs(ret, "profiles", profiles);
      putNameTypeConfs(ret, "keypairGens", keypairGens);
      if (cas != null) {
        JsonList list = new JsonList();
        ret.put("cas", list);

        for (Ca ca : cas) {
          list.add(ca.toCodec());
        }
      }

      return ret;
    }

  } // class CaSystem

  public static class CaHasRequestor implements JsonEncodable {

    private final String requestorName;

    private final Permissions permissions;

    private final List<String> profiles;

    public CaHasRequestor(String requestorName, Permissions permissions,
                          List<String> profiles) {
      this.requestorName = StringUtil.lowercase(requestorName);
      this.permissions = Args.notNull(permissions, "permissions");
      this.profiles = profiles;
    }

    public String requestorName() {
      return requestorName;
    }

    public Permissions permissions() {
      return permissions;
    }

    public List<String> profiles() {
      return profiles;
    }

    public static CaHasRequestor parse(JsonMap json) throws CodecException {
      Permissions permissions = Permissions.parseJson(
          json.getNnObject("permissions"));
      return new CaHasRequestor(
          json.getString("requestorName"),
          permissions,
          json.getStringList("profiles"));
    }

    public JsonMap toCodec() {
      JsonMap map = new JsonMap();
      map.put("requestorName", requestorName);
      map.putStrings("profiles", profiles);
      map.putStrings("permissions", permissions.toPermissionTexts());
      return map;
    }

  } // class CaHasRequestor

  public static class CaInfo implements JsonEncodable {

    private final BaseCaInfo base;

    /**
     * If genSelfIssued is preset, it must be absent; Otherwise it specifies
     * the CA certificate
     */
    private FileOrBinary cert;

    /**
     * Certificate chain without the certificate specified in {@code #cert}.
     */
    private List<FileOrBinary> certchain;

    /**
     * A new self-issued CA certificate will be generated.
     */
    private GenSelfIssued genSelfIssued;

    private final FileOrValue signerConf;

    public CaInfo(BaseCaInfo base, FileOrValue signerConf,
                  GenSelfIssued genSelfIssued) {
      this.base = Args.notNull(base, "base");
      this.genSelfIssued = Args.notNull(genSelfIssued, "genSelfIssued");
      this.signerConf    = Args.notNull(signerConf, "signerConf");
      this.cert      = null;
      this.certchain = null;
    }

    public CaInfo(BaseCaInfo base, FileOrValue signerConf,
                  FileOrBinary cert, List<FileOrBinary> certchain) {
      this.base = Args.notNull(base, "base");
      this.cert = Args.notNull(cert, "cert");
      this.certchain = certchain;
      this.signerConf = Args.notNull(signerConf, "signerConf");
      this.genSelfIssued = null;
    }

    public BaseCaInfo base() {
      return base;
    }

    public GenSelfIssued genSelfIssued() {
      return genSelfIssued;
    }

    public FileOrValue signerConf() {
      return signerConf;
    }

    public FileOrBinary cert() {
      return cert;
    }

    public void setCert(FileOrBinary cert) {
      this.genSelfIssued = null;
      this.cert = Args.notNull(cert, "cert");
    }

    public List<FileOrBinary> getCertchain() {
      return certchain;
    }

    public void setCertchain(List<FileOrBinary> certchain) {
      this.certchain = certchain;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      base.toJson(ret);

      ret.put("genSelfIssued", genSelfIssued);
      ret.put("cert", cert);
      ret.put("signerConf", signerConf);

      if (certchain != null) {
        JsonList list = new JsonList();
        ret.put("certchain", list);
        for (FileOrBinary cert : certchain) {
          list.add(cert.toCodec());
        }
      }

      return ret;
    }

    public static CaInfo parse(JsonMap json) throws CodecException {
      BaseCaInfo base = BaseCaInfo.parse(json);

      FileOrValue signerConf = FileOrValue.parse(json.getNnMap("signerConf"));

      JsonMap map = json.getMap("genSelfIssued");
      CaInfo caInfo;
      if (map != null) {
        caInfo = new CaInfo(base, signerConf, GenSelfIssued.parse(map));
      } else {
        caInfo = new CaInfo(base, signerConf,
            FileOrBinary.parse(json.getMap("cert")),
            FileOrBinary.parseList(json.getList("certchain")));
      }

      return caInfo;
    }

  } // class CaInfo

  public static class IdNameConf implements JsonEncodable {

    private Integer id;

    private final String name;

    public IdNameConf(Integer id, String name) {
      try {
        CaConfs.checkName(name, "name");
      } catch (InvalidConfException e) {
        throw new IllegalArgumentException(e);
      }
      this.name = StringUtil.lowercase(name);
      this.id = id;
    }

    public Integer id() {
      return id;
    }

    public void setId(Integer id) {
      this.id = id;
    }

    public String name() {
      return name;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      toJson(ret);
      return ret;
    }

    protected void toJson(JsonMap map) {
      map.put("id", id);
      map.put("name", name);
    }

    public static IdNameConf parse(JsonMap json) throws CodecException {
      return new IdNameConf(json.getInt("id"), json.getNnString("name"));
    }

  }

  public static class Ca extends IdNameConf {

    private final CaInfo caInfo;

    private final List<String> aliases;

    private final List<String> profiles;

    private final List<CaHasRequestor> requestors;

    private final List<String> publishers;

    public Ca(Integer id, String name, CaInfo caInfo, List<String> aliases,
              List<String> profiles, List<CaHasRequestor> requestors,
              List<String> publishers) {
      super(id, name);
      this.caInfo     = Args.notNull(caInfo, "caInfo");
      this.profiles   = (profiles   == null ? new LinkedList<>()
          : StringUtil.lowercase(profiles));
      this.requestors = (requestors == null ? new LinkedList<>() : requestors);
      this.publishers = (publishers == null ? new LinkedList<>()
          : StringUtil.lowercase(publishers));

      if (aliases == null) {
        this.aliases = new LinkedList<>();
      } else {
        for (String alias : aliases) {
          try {
            CaConfs.checkName(alias, "CA alias");
          } catch (InvalidConfException e) {
            throw new IllegalArgumentException(e);
          }
        }
        this.aliases = aliases;
      }
    }

    public CaInfo caInfo() {
      return caInfo;
    }

    public List<String> aliases() {
      return aliases;
    }

    public List<String> profiles() {
      return profiles;
    }

    public List<CaHasRequestor> requestors() {
      return requestors;
    }

    public List<String> publishers() {
      return publishers;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);

      if (caInfo != null) {
        ret.put("caInfo", caInfo.toCodec());
      }

      if (!aliases.isEmpty()) {
        ret.putStrings("aliases", aliases);
      }

      if (!profiles.isEmpty()) {
        ret.putStrings("profiles", profiles);
      }

      if (!publishers.isEmpty()) {
        ret.putStrings("publishers", publishers);
      }

      if (!requestors.isEmpty()) {
        ret.putEncodables("requestors", requestors);
      }

      return ret;
    }

    public static Ca parse(JsonMap json) throws CodecException {
      List<CaHasRequestor> requestors = null;

      JsonList list = json.getList("requestors");
      if (list != null) {
        requestors = new ArrayList<>(list.size());
        for (JsonMap m : list.toMapList()) {
          requestors.add(CaHasRequestor.parse(m));
        }
      }

      return new Ca(
          json.getInt("id"),
          json.getNnString("name"),
          CaInfo.parse(json.getNnMap("caInfo")),
          json.getStringList("aliases"),
          json.getStringList("profiles"),
          requestors,
          json.getStringList("publishers"));
    }

  } // class Ca

  public static class GenSelfIssued implements JsonEncodable {

    private final String subject;

    private String profile;

    private String serialNumber;

    private String notBefore;

    private String notAfter;

    public GenSelfIssued(String subject) {
      this.subject = Args.notBlank(subject, "subject");
    }

    public String subject() {
      return subject;
    }

    public String profile() {
      return profile;
    }

    public void setProfile(String profile) {
      this.profile = profile;
    }

    public String serialNumber() {
      return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
      this.serialNumber = serialNumber;
    }

    public String notBefore() {
      return notBefore;
    }

    public void notBefore(String notBefore) {
      this.notBefore = notBefore;
    }

    public String notAfter() {
      return notAfter;
    }

    public void setNotAfter(String notAfter) {
      this.notAfter = notAfter;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap map = new JsonMap();
      map.put("subject", subject);
      map.put("profile", profile);
      map.put("serialNumber", serialNumber);
      map.put("notBefore", notBefore);
      map.put("notAfter", notAfter);
      return map;
    }

    public static GenSelfIssued parse(JsonMap json) throws CodecException {
      GenSelfIssued ret = new GenSelfIssued(json.getNnString("subject"));
      ret.setProfile(json.getString("profile"));
      ret.setSerialNumber(json.getString("serialNumber"));
      ret.notBefore(json.getString("notBefore"));
      ret.setNotAfter(json.getString("notAfter"));
      return ret;
    }

  } // class GenSelfIssued

  public static class NameTypeConf extends IdNameConf {

    private final String type;

    private final FileOrValue conf;

    public NameTypeConf(Integer id, String name,
                        String type, FileOrValue conf) {
      super(id, name);
      this.type = Args.notBlank(type, "type");
      this.conf = conf;
    }

    public String type() {
      return type;
    }

    public FileOrValue conf() {
      return conf;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      this.toJson(ret);
      return ret;
    }

    @Override
    protected void toJson(JsonMap map) {
      super.toJson(map);
      map.put("type", type);
      map.put("conf", conf);
    }

    public static NameTypeConf parse(JsonMap json) throws CodecException {
      return new NameTypeConf(json.getInt("id"), json.getNnString("name"),
          json.getNnString("type"), FileOrValue.parse(json.getMap("conf")));
    }

  } // class NameTypeConf

  public static class Requestor extends IdNameConf {

    private final String type;

    private final FileOrValue conf;

    private final FileOrBinary binaryConf;

    public Requestor(Integer id, String name, String type, FileOrValue conf) {
      super(id, name);
      this.type = Args.notBlank(type, "type");
      this.conf = Args.notNull(conf, "conf");
      this.binaryConf = null;
    }

    public Requestor(Integer id, String name, String type,
                     FileOrBinary binaryConf) {
      super(id, name);
      this.type = Args.notBlank(type, "type");
      this.binaryConf = Args.notNull(binaryConf, "binaryConf");
      this.conf = null;
    }

    public String type() {
      return type;
    }

    public FileOrValue conf() {
      return conf;
    }

    public FileOrBinary binaryConf() {
      return binaryConf;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("type", type);
      ret.put("conf", conf);
      ret.put("binaryConf", binaryConf);
      return ret;
    }

    public static Requestor parse(JsonMap json) throws CodecException {
      FileOrValue conf = FileOrValue.parse(json.getMap("conf"));
      FileOrBinary binaryConf = FileOrBinary.parse(json.getMap("binaryConf"));

      if (conf == null && binaryConf == null) {
        throw new IllegalArgumentException(
            "conf and binaryConf may not be both null");
      } else if (conf != null && binaryConf != null) {
        throw new IllegalArgumentException(
            "conf and binaryConf may not be both non-null");
      }

      String name = json.getNnString("name");
      String type = json.getNnString("type");
      Integer id = json.getInt("id");

      return (conf != null) ? new Requestor(id, name, type, conf)
          : new Requestor(id, name, type, binaryConf);
    }

  } // class Requestor

  public static class Signer extends NameTypeConf {

    private final FileOrBinary cert;

    public Signer(Integer id, String name, String type,
                  FileOrValue conf, FileOrBinary cert) {
      super(id, name, type, conf);
      this.cert = cert;
    }

    public FileOrBinary cert() {
      return cert;
    }

    public static Signer parse(JsonMap json) throws CodecException {
      return new Signer(json.getInt("id"), json.getNnString("name"),
          json.getNnString("type"), FileOrValue.parse(json.getMap("conf")),
          FileOrBinary.parse(json.getMap("cert")));
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("cert", cert);
      return ret;
    }

  } // class Signer

}
