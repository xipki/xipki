// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.xipki.ca.sdk.SdkClientConf;
import org.xipki.security.Securities;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.audit.Audits;
import org.xipki.util.extra.type.KeystoreConf;
import org.xipki.util.io.FileOrBinary;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 *
 * @author Lijun Liao (xipki)
 * Gateway Conf configuration.
 */

public class GatewayConf {

  /**
   * Supported Protocols.
   *
   * @author Lijun Liao (xipki)
   */
  public static class SupportedProtocols {

    private boolean acme;

    private boolean cmp;

    private boolean est;

    private boolean rest;

    private boolean scep;

    public boolean isAcme() {
      return acme;
    }

    public void setAcme(boolean acme) {
      this.acme = acme;
    }

    public boolean isCmp() {
      return cmp;
    }

    public void setCmp(boolean cmp) {
      this.cmp = cmp;
    }

    public boolean isEst() {
      return est;
    }

    public void setEst(boolean est) {
      this.est = est;
    }

    public boolean isRest() {
      return rest;
    }

    public void setRest(boolean rest) {
      this.rest = rest;
    }

    public boolean isScep() {
      return scep;
    }

    public void setScep(boolean scep) {
      this.scep = scep;
    }

    public static SupportedProtocols parse(JsonMap json) throws CodecException {
      SupportedProtocols ret = new SupportedProtocols();
      ret.setAcme(json.getBool("acme", false));
      ret.setCmp (json.getBool("cmp",  false));
      ret.setEst (json.getBool("est",  false));
      ret.setRest(json.getBool("rest", false));
      ret.setScep(json.getBool("scep", false));
      return ret;
    }
  }

  private final SupportedProtocols protocols;

  private final PopControlConf pop;

  private final SdkClientConf sdkClient;

  private final Audits.AuditConf audit;

  private final Securities.SecurityConf security;

  private boolean logReqResp;

  private String reverseProxyMode;

  public GatewayConf(SupportedProtocols protocols, PopControlConf pop,
                    SdkClientConf sdkClient, Audits.AuditConf audit,
                    Securities.SecurityConf security) {
    this.protocols = Args.notNull(protocols, "protocols");
    this.pop = Args.notNull(pop, "pop");
    this.sdkClient = Args.notNull(sdkClient, "sdkClient");
    this.audit = Args.notNull(audit, "audit");
    this.security = Args.notNull(security, "security");
  }

  public static GatewayConf readConfFromFile(String fileName)
      throws InvalidConfException {
    Args.notBlank(fileName, "fileName");
    try {
      JsonMap map = JsonParser.parseMap(Path.of(fileName), true);
      return GatewayConf.parse(map);
    } catch (CodecException e) {
      throw new InvalidConfException("invalid GatewayConf: " + fileName, e);
    }
  }

  public boolean isLogReqResp() {
    return logReqResp;
  }

  public void setLogReqResp(boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  public String reverseProxyMode() {
    return reverseProxyMode;
  }

  public void setReverseProxyMode(String reverseProxyMode) {
    this.reverseProxyMode = reverseProxyMode;
  }

  public PopControlConf pop() {
    return pop;
  }

  public SdkClientConf sdkClient() {
    return sdkClient;
  }

  public Audits.AuditConf audit() {
    return audit;
  }

  public Securities.SecurityConf security() {
    return security;
  }

  public SupportedProtocols protocols() {
    return protocols;
  }

  public static GatewayConf parse(JsonMap json) throws CodecException {
    JsonMap map = json.getMap("protocols");
    SupportedProtocols protocols = (map == null) ? null : SupportedProtocols.parse(map);

    map = json.getMap("pop");
    PopControlConf pop = (map == null) ? null : PopControlConf.parse(map);

    map = json.getMap("sdkClient");
    SdkClientConf sdkClient = (map == null) ? null : SdkClientConf.parse(map);

    map = json.getMap("audit");
    Audits.AuditConf audit = (map == null) ? null : Audits.AuditConf.parse(map);

    map = json.getMap("security");
    Securities.SecurityConf security = (map == null) ? null : Securities.SecurityConf.parse(map);

    GatewayConf ret = new GatewayConf(protocols, pop, sdkClient, audit, security);
    Boolean b = json.getBool("logReqResp");
    if (b != null) {
      ret.setLogReqResp(b);
    }

    String str = json.getString("reverseProxyMode");
    if (str != null) {
      ret.setReverseProxyMode(str);
    }

    return ret;
  }

  /**
   *
   * @author Lijun Liao (xipki)
   * CA Name Signer Conf configuration.
   */

  public static class CaNameSignerConf {

    private final List<String> names;

    private final SignerConf signer;

    public CaNameSignerConf(SignerConf signer, List<String> names) {
      this.names  = names;
      this.signer = signer;
    }

    public List<String> names() {
      return names;
    }

    public SignerConf signer() {
      return signer;
    }

    public static CaNameSignerConf parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("signer");
      SignerConf signer = (map == null) ? null : SignerConf.parse(map);
      return new CaNameSignerConf(signer, json.getStringList("names"));
    }

  }

  /**
   *
   * @author Lijun Liao (xipki)
   * CA Name Signers Conf configuration.
   */

  public static class CaNameSignersConf {

    private final SignerConf default_;

    private final List<CaNameSignerConf> signers;

    public CaNameSignersConf(SignerConf default_, List<CaNameSignerConf> signers) {
      this.default_ = default_;
      this.signers = signers;
    }

    public SignerConf getDefault() {
      return default_;
    }

    public List<CaNameSignerConf> signers() {
      return signers;
    }

    public static CaNameSignersConf parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("default");
      SignerConf default_ = (map == null) ? null : SignerConf.parse(map);
      JsonList list = json.getList("signers");
      List<CaNameSignerConf> signers = null;
      if (list != null) {
        signers = new ArrayList<>(list.size());
        for (JsonMap v : list.toMapList()) {
          signers.add(CaNameSignerConf.parse(v));
        }
      }

      return new CaNameSignersConf(default_, signers);
    }

  }

  /**
   * CA Profile Conf configuration.
   *
   * @author Lijun Liao (xipki)
   */
  public static class CaProfileConf {

    private final String name;

    private final String ca;

    private final String certprofile;

    public CaProfileConf(String name, String ca, String certprofile) {
      this.name = Args.toNonBlankLower(name, "name");
      this.ca = Args.notBlank(ca, "ca");
      this.certprofile = Args.notBlank(certprofile, "certprofile");
    }

    public String name() {
      return name;
    }

    public String ca() {
      return ca;
    }

    public String certprofile() {
      return certprofile;
    }

    public static CaProfileConf parse(JsonMap json) throws CodecException {
      return new CaProfileConf(json.getNnString("name"),
          json.getNnString("ca"), json.getNnString("certprofile"));
    }

  }

  /**
   * CA Profiles Control control settings.
   *
   * @author Lijun Liao (xipki)
   */
  public static class CaProfilesControl {

    private final List<CaProfileConf> caProfiles;

    public CaProfilesControl(List<CaProfileConf> caProfiles) throws InvalidConfException {
      if (caProfiles == null) {
        this.caProfiles = new ArrayList<>();
      } else {
        for (CaProfileConf conf : caProfiles) {
          if (conf == null) {
            throw new InvalidConfException("caProfiles must not contain null element");
          }
        }
        this.caProfiles = caProfiles;
      }

      Set<String> names = new HashSet<>();
      for (CaProfileConf entry : this.caProfiles) {
        String name = entry.name();
        checkName(name, "caProfile name");
        if (names.contains(name)) {
          throw new InvalidConfException("caProfile " + name + " duplicated");
        }

        names.add(name);
      }
    }

    public CaProfileConf getCaProfile(String name) {
      for (CaProfileConf conf : caProfiles) {
        if (conf.name().equalsIgnoreCase(name)) {
          return conf;
        }
      }
      return null;
    }

    private static void checkName(String param, String paramName) throws InvalidConfException {
      if (param == null || param.isEmpty()) {
        throw new InvalidConfException(paramName + " must not be blank");
      }

      for (int i = 0; i < param.length(); i++) {
        char c = param.charAt(i);
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
            || (c >= 'A' && c <= 'Z') || (c == '-') || (c == '_') || (c == '.')) {
          continue;
        }

        throw new InvalidConfException("invalid char '" + c + "' in " + paramName);
      }
    }

  }

  /**
   * Pop Control Conf configuration.
   *
   * @author Lijun Liao (xipki)
   */
  public static class PopControlConf {

    private final List<String> sigAlgos;

    private final KeystoreConf dh;

    private final KeystoreConf kem;

    public PopControlConf(List<String> sigAlgos, KeystoreConf dh, KeystoreConf kem) {
      this.sigAlgos = sigAlgos;
      this.dh = dh;
      this.kem = kem;
    }

    public List<String> sigAlgos() {
      return this.sigAlgos;
    }

    public KeystoreConf dh() {
      return this.dh;
    }

    public KeystoreConf kem() {
      return this.kem;
    }

    public static PopControlConf parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("dh");
      KeystoreConf dh = (map == null) ? null : KeystoreConf.parse(map);

      map = json.getMap("kem");
      KeystoreConf kem = (map == null) ? null : KeystoreConf.parse(map);
      return new PopControlConf(json.getStringList("sigAlgos"), dh, kem);
    }

  }

  /**
   *
   * @author Lijun Liao (xipki)
   * Protocol Conf configuration.
   */

  public static class ProtocolConf {

    private final Boolean logReqResp;

    private final PopControlConf pop;

    private final SdkClientConf sdkClient;

    public ProtocolConf(Boolean logReqResp, PopControlConf pop, SdkClientConf sdkClient) {
      this.logReqResp = logReqResp;
      this.pop = pop;
      this.sdkClient = sdkClient;
    }

    public Boolean logReqResp() {
      return logReqResp;
    }

    public PopControlConf pop() {
      return pop;
    }

    public SdkClientConf sdkClient() {
      return sdkClient;
    }

    public static ProtocolConf parse0(JsonMap json) throws CodecException {
      Boolean logReqResp = json.getBool("logReqResp");
      JsonMap map = json.getMap("pop");
      PopControlConf pop = (map == null) ? null : PopControlConf.parse(map);
      map = json.getMap("sdkClient");
      SdkClientConf sdkClientConf = (map == null) ? null : SdkClientConf.parse(map);
      return new ProtocolConf(logReqResp, pop, sdkClientConf);
    }

  }

  /**
   *
   * @author Lijun Liao (xipki)
   * Signer Conf configuration.
   */

  public static class SignerConf {

    private final List<FileOrBinary> certs;

    private final String type;

    private final String conf;

    public SignerConf(String type, String conf, List<FileOrBinary> certs) {
      this.type = Args.notBlank(type, "type");
      this.conf = Args.notBlank(conf, "conf");
      this.certs = certs;
    }

    public List<FileOrBinary> certs() {
      return certs;
    }

    public String type() {
        return type;
    }

    public String conf() {
      return conf;
    }

    public static SignerConf parse(JsonMap json) throws CodecException {
      return new SignerConf(json.getNnString("type"),
          json.getNnString("conf"), FileOrBinary.parseList(json.getList("certs")));
    }

  }
}
