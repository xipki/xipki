// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * CA CertStore configuration.
 *
 * @author Lijun Liao (xipki)
 */

public class CaCertstore implements JsonEncodable {

  private int version;

  private int countCrls;

  private int countCerts;

  private List<Ca> cas;

  private List<IdName> requestors;

  private List<IdName> profiles;

  public int getVersion() {
    return version;
  }

  public void setVersion(int version) {
    this.version = version;
  }

  public int getCountCrls() {
    return countCrls;
  }

  public void setCountCrls(int countCrls) {
    this.countCrls = countCrls;
  }

  public int getCountCerts() {
    return countCerts;
  }

  public void setCountCerts(int countCerts) {
    this.countCerts = countCerts;
  }

  public List<Ca> getCas() {
    return cas;
  }

  public void setCas(List<Ca> cas) {
    this.cas = cas;
  }

  public List<IdName> getRequestors() {
    return requestors;
  }

  public void setRequestors(List<IdName> requestors) {
    this.requestors = requestors;
  }

  public List<IdName> getProfiles() {
    return profiles;
  }

  public void setProfiles(List<IdName> profiles) {
    this.profiles = profiles;
  }

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();
    ret.put("version", version);
    ret.put("countCrls", countCrls);
    ret.put("countCerts", countCerts);
    ret.putEncodables("cas", cas);
    ret.putEncodables("requestors", requestors);
    ret.putEncodables("profiles", profiles);
    return ret;
  }

  public static CaCertstore parse(JsonMap json) throws CodecException {
    CaCertstore ret = new CaCertstore();
    ret.setVersion(json.getNnInt("version"));
    ret.setCountCrls(json.getNnInt("countCrls"));
    ret.setCountCerts(json.getNnInt("countCerts"));

    JsonList list = json.getList("cas");
    if (list != null) {
      List<Ca> cas = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        cas.add(Ca.parse(v));
      }
      ret.setCas(cas);
    }

    list = json.getList("requestors");
    if (list != null) {
      ret.setRequestors(IdName.parse(list));
    }

    list = json.getList("profiles");
    if (list != null) {
      ret.setProfiles(IdName.parse(list));
    }

    return ret;
  }

  public static class Cert extends IdentifiedDbObject {

    private final String file;

    private String privateKeyFile;

    private final int caId;

    /**
     * certificate serial number.
     */
    private final String sn;

    /**
     * certificate profile id.
     */
    private final int pid;

    /**
     * requestor id.
     */
    private final int rid;

    private final boolean ee;

    private final long update;

    /**
     * whether revoked.
     */
    private int rev;

    /**
     * revocation reason.
     */
    private Integer rr;

    /**
     * revocation time.
     */
    private Long rt;

    /**
     * revocation invalidity time.
     */
    private Long rit;

    /**
     * base64 encoded transaction id.
     */
    private String tid;

    /**
     * first 8 bytes of the SHA1 sum of the requested subject.
     */
    private Long fpRs;

    private final int crlScope;

    /**
     * requested subject, if differs from the one in certificate.
     */
    private String rs;

    public Cert(long id, String file, int caId, String sn, int pid, int rid,
                boolean ee, long update, int crlScope) {
      super(id);
      this.file = Args.notBlank(file, "file");
      this.caId = caId;
      this.sn = Args.notBlank(sn, "sn");
      this.pid = pid;
      this.rid = rid;
      this.ee = ee;
      this.update = update;
      this.crlScope = crlScope;
    }

    public void setRevocation(int revocationReason, long revocationTime,
                              Long invalidityTime) {
      this.rr = revocationReason;
      this.rt = revocationTime;
      this.rit = invalidityTime;
      this.rev = 1;
    }

    public String getFile() {
      return file;
    }

    public String getPrivateKeyFile() {
      return privateKeyFile;
    }

    public void setPrivateKeyFile(String privateKeyFile) {
      this.privateKeyFile = privateKeyFile;
    }

    public int getCaId() {
      return caId;
    }

    public String getSn() {
      return sn;
    }

    public int getPid() {
      return pid;
    }

    public int getRid() {
      return rid;
    }

    public boolean isEe() {
      return ee;
    }

    public long getUpdate() {
      return update;
    }

    public int getRev() {
      return rev;
    }

    public Integer getRr() {
      return rr;
    }

    public Long getRt() {
      return rt;
    }

    public Long getRit() {
      return rit;
    }

    public String getTid() {
      return tid;
    }

    public void setTid(String tid) {
      this.tid = tid;
    }

    public Long getFpRs() {
      return fpRs;
    }

    public void setFpRs(Long fpRs) {
      this.fpRs = fpRs;
    }

    public int getCrlScope() {
      return crlScope;
    }

    public String getRs() {
      return rs;
    }

    public void setRs(String rs) {
      this.rs = rs;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);

      return ret.put("file", file).put("privateKeyFile", privateKeyFile)
          .put("caId", caId).put("sn", sn).put("pid", pid).put("rid", rid)
          .put("ee",  ee).put("update", update).put("rev", rev).put("rr", rr)
          .put("rt", rt).put("rit", rit).put("tid", tid).put("fpRs", fpRs)
          .put("crlScope", crlScope).put("rs", rs);
    }

    public static Cert parse(JsonMap json) throws CodecException {
      Cert ret = new Cert(json.getNnInt("id"),
          json.getString("file"),   json.getNnInt("caId"),
          json.getString("sn"),     json.getNnInt("pid"),
          json.getNnInt("rid"),     json.getNnBool("ee"),
          json.getNnLong("update"), json.getNnInt("crlScope"));

      ret.setPrivateKeyFile(json.getString("privateKeyFile"));
      int rev = json.getNnInt("rev");
      if (rev != 0) {
        ret.setRevocation(json.getNnInt("rr"),
            json.getNnLong("rt"), json.getLong("rit"));
      }
      ret.setTid(json.getString("tid"));
      ret.setFpRs(json.getLong("fpRs"));
      ret.setRs(json.getString("rs"));
      return ret;
    }
  } // method Cert

  public static class Certs implements JsonEncodable {

    private final List<Cert> certs;

    public Certs(List<Cert> certs) {
      this.certs = Args.notNull(certs, "certs");
    }

    public List<Cert> getCerts() {
      return certs;
    }

    public void add(Cert cert) {
      certs.add(cert);
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.putEncodables("certs", certs);
      return ret;
    }

    public static Certs parse(JsonMap json) throws CodecException {
      JsonList list = json.getNnList("certs");
      List<Cert> certs = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        certs.add(Cert.parse(v));
      }
      return new Certs(certs);
    }

  } // class Certs

  public static class Crl extends IdentifiedDbObject {

    private final int caId;

    private final String crlNo;

    private final String file;

    private final int crlScope;

    public Crl(long id, int caId, String file, String crlNo, int crlScope) {
      super(id);
      this.caId = caId;
      this.file = Args.notBlank(file, "file");
      this.crlNo = Args.notBlank(crlNo, "crlNo");
      this.crlScope = crlScope;
    }

    public Integer getCaId() {
      return caId;
    }

    public String getCrlNo() {
      return crlNo;
    }

    public Integer getCrlScope() {
      return crlScope;
    }

    public String getFile() {
      return file;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      return ret.put("caId", caId).put("file", file)
          .put("crlNo", crlNo).put("crlScope", crlScope);
    }

    public static Crl parse(JsonMap json) throws CodecException {
      return new Crl(json.getNnInt("id"), json.getNnInt("caId"),
          json.getNnString("file"), json.getNnString("crlNo"),
          json.getNnInt("crlScope"));
    }

  } // class CaHasEntry

  public static class Crls implements JsonEncodable {

    private final List<Crl> crls;

    public Crls(List<Crl> crls) {
      this.crls = Args.notNull(crls, "crls");
    }

    public List<Crl> getCrls() {
      return crls;
    }

    public void add(Crl crl) {
      crls.add(crl);
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().putEncodables("crls", crls);
    }

    public static Crls parse(JsonMap json) throws CodecException {
      JsonList list = json.getNnList("crls");
      List<Crl> crls = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        crls.add(Crl.parse(v));
      }
      return new Crls(crls);
    }

  } // class Crls

  public static class IdName implements JsonEncodable {

    private final int id;

    private final String name;

    public IdName(int id, String name) {
      this.id = id;
      this.name = Args.notNull(name, "name");
    }

    public int getId() {
      return id;
    }

    public String getName() {
      return name;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      toJson(ret);
      return ret;
    }

    protected void toJson(JsonMap json) {
      json.put("id", id).put("name", name);
    }

    public static IdName parse(JsonMap json) throws CodecException {
      return new IdName(json.getNnInt("id"), json.getNnString("name"));
    }

    public static List<IdName> parse(JsonList json) throws CodecException {
      List<IdName> list = new ArrayList<>(json.size());
      for (JsonMap v : json.toMapList()) {
        list.add(IdName.parse(v));
      }
      return list;
    }

  }

  public static class Ca extends IdName {

    private final String revInfo;

    private final byte[] cert;

    public Ca(int id, String name, byte[] cert, String revInfo) {
      super(id, name);
      this.cert = Args.notNull(cert, "cert");
      this.revInfo = revInfo;
    }

    public byte[] getCert() {
      return cert;
    }

    public String getRevInfo() {
      return revInfo;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      return ret.put("cert", cert).put("revInfo", revInfo);
    }

    public static Ca parse(JsonMap json) throws CodecException {
      return new Ca(json.getNnInt("id"), json.getNnString("name"),
          json.getNnBytes("certs"), json.getString("revInfo"));
    }

  }

}
