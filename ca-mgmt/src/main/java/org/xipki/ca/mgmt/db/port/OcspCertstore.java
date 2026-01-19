// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * OCSP CertStore.
 *
 * @author Lijun Liao (xipki)
 */

public class OcspCertstore implements JsonEncodable {

  public static class Cert extends IdentifiedDbObject {

    private final String hash;

    private final int iid;

    private final long nbefore;

    private final long nafter;

    private final String sn;

    private final String subject;

    private final long update;

    private final Integer crlId;

    private boolean rev;

    private Long rit;

    private Integer rr;

    private Long rt;

    public Cert(long id, String hash, int iid, long update, long nbefore,
                long nafter, String sn, String subject, Integer crlId) {
      super(id);
      this.hash = Args.notNull(hash, "hash");
      this.iid = iid;
      this.nbefore = nbefore;
      this.nafter = nafter;
      this.sn = Args.notNull(sn, "sn");
      this.subject = Args.notNull(subject, "subject");
      this.update = update;
      this.crlId = crlId;
    }

    public String getHash() {
      return hash;
    }

    public int getIid() {
      return iid;
    }

    public long getNafter() {
      return nafter;
    }

    public long getNbefore() {
      return nbefore;
    }

    public String getSn() {
      return sn;
    }

    public String getSubject() {
      return subject;
    }

    public long getUpdate() {
      return update;
    }

    public Integer getCrlId() {
      return crlId;
    }

    public boolean isRev() {
      return rev;
    }

    public void setRevocation(
        int reason, long revocationTime, Long revocationInvalidityTime) {
      this.rev = true;
      this.rr = reason;
      this.rt = revocationTime;
      this.rit = revocationInvalidityTime;
    }

    public Long getRit() {
      return rit;
    }

    public Integer getRr() {
      return rr;
    }

    public Long getRt() {
      return rt;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);

      return ret.put("hash", hash).put("iid", iid).put("nafter", nafter)
          .put("nbefore", nbefore).put("sn", sn).put("subject", subject)
          .put("update", update).put("crlId", crlId).put("rev", rev)
          .put("rit", rit).put("rr", rr).put("rt", rt);
    }

    public static Cert parse(JsonMap json) throws CodecException {
      // long id, String hash, int iid, long update, long nafter, long nbefore,
      //                String sn, String subject, Integer crlId
      Cert ret = new Cert(json.getNnLong("id"),
          json.getNnString("hash"), json.getNnInt("iid"),
          json.getNnLong("update"), json.getNnLong("nbefore"),
          json.getNnLong("nafter"), json.getNnString("sn"),
          json.getNnString("subject"), json.getInt("crlId"));
      boolean revoked = json.getBool("rev", false);
      if (revoked) {
        ret.setRevocation(json.getNnInt("rr"),
            json.getNnLong("rt"), json.getLong("rit"));
      }
      return ret;
    }
  }

  public static class Certs implements JsonEncodable {

    private final List<Cert> certs;

    public Certs() {
      this.certs = new LinkedList<>();
    }

    public Certs(List<Cert> certs) {
      this.certs = Args.notNull(certs, "certs");
    }

    public List<Cert> getCerts() {
      return certs;
    }

    public void add(Cert cert) {
      getCerts().add(cert);
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().putEncodables("certs", certs);
    }

    public static Certs parse(JsonMap json) throws CodecException {
      JsonList list = json.getNnList("certs");
      List<Cert> certs = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        certs.add(Cert.parse(v));
      }
      return new Certs(certs);
    }

  } // class Cert

  public static class Issuer implements JsonEncodable {

    private final int id;

    private final Integer crlId;

    private final String certFile;

    private final String revInfo;

    public Issuer(int id, String certFile, String revInfo, Integer crlId) {
      this.id = id;
      this.certFile = Args.notNull(certFile, "certFile");
      this.revInfo = revInfo;
      this.crlId = crlId;
    }

    public int getId() {
      return id;
    }

    public String getCertFile() {
      return certFile;
    }

    public String getRevInfo() {
      return revInfo;
    }

    public Integer getCrlId() {
      return crlId;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("id", id).put("certFile", certFile)
          .put("revInfo", revInfo).put("crlId", crlId);
    }

    public static Issuer parse(JsonMap json) throws CodecException {
      return new Issuer(json.getNnInt("id"),
          json.getNnString("certFile"), json.getString("revInfo"),
          json.getInt("crlId"));
    }

  } // class Issuer

  public static class CrlInfo implements JsonEncodable {

    private final int id;

    private final String name;

    private final String info;

    public CrlInfo(int id, String name, String info) {
      this.id = id;
      this.name = Args.notBlank(name, "name");
      this.info = Args.notBlank(info, "info");
    }

    public int getId() {
      return id;
    }

    public String getName() {
      return name;
    }

    public String getInfo() {
      return info;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("id", id).put("name", name).put("info", info);
    }

    public static CrlInfo parse(JsonMap json) throws CodecException {
      return new CrlInfo(json.getNnInt("id"),
          json.getNnString("name"), json.getNnString("info"));
    }

  } // class CrlInfo

  private final int version;

  private int countCerts;

  private String certhashAlgo;

  private final List<Issuer> issuers;

  private final List<CrlInfo> crlInfos;

  public OcspCertstore(int version, int countCerts, String certhashAlgo,
                       List<Issuer> issuers, List<CrlInfo> crlInfos) {
    this.version = version;
    this.countCerts = countCerts;
    this.certhashAlgo = certhashAlgo;
    this.issuers  = (issuers  == null) ? new LinkedList<>() : issuers;
    this.crlInfos = (crlInfos == null) ? new LinkedList<>() : crlInfos;
  }

  public OcspCertstore(int version) {
    this.version = version;
    this.issuers  = new LinkedList<>();
    this.crlInfos = new LinkedList<>();
  }

  public int getVersion() {
    return version;
  }

  public int getCountCerts() {
    return countCerts;
  }

  public String getCerthashAlgo() {
    return certhashAlgo;
  }

  public List<Issuer> getIssuers() {
    return issuers;
  }

  public List<CrlInfo> getCrlInfos() {
    return crlInfos;
  }

  public void setCountCerts(int countCerts) {
    this.countCerts = countCerts;
  }

  public void setCerthashAlgo(String certhashAlgo) {
    this.certhashAlgo = certhashAlgo;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("version", version).put("countCerts", countCerts)
        .put("certhashAlgo", certhashAlgo).putEncodables("issuers",  issuers)
        .putEncodables("crlInfos", crlInfos);
  }

  public static OcspCertstore parse(JsonMap json) throws CodecException {
    JsonList list = json.getList("issuers");
    List<Issuer> issuers;
    if (list == null) {
      issuers = new ArrayList<>(1);
    } else {
      issuers = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        issuers.add(Issuer.parse(v));
      }
    }

    list = json.getList("crlInfos");
    List<CrlInfo> crlInfos;
    if (list == null) {
      crlInfos = new ArrayList<>(1);
    } else {
      crlInfos = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        crlInfos.add(CrlInfo.parse(v));
      }
    }

    return new OcspCertstore(json.getNnInt("version"),
        json.getNnInt("countCerts"), json.getString("certhashAlgo"),
        issuers, crlInfos);
  }

}
