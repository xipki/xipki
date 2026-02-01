// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CA Management response via the REST API.
 *
 * @author Lijun Liao (xipki)
 */

public abstract class MgmtResponse extends MgmtMessage {

  public static class GetDbSchemas extends MgmtResponse {

    private Map<String, String> result;

    public GetDbSchemas(Map<String, String> result) {
      this.result = result;
    }

    public Map<String, String> result() {
      return result;
    }

    public void setResult(Map<String, String> result) {
      this.result = result;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.putStringMap("result", result);
      return null;
    }

    public static GetDbSchemas parse(JsonMap json) throws CodecException {
      return new GetDbSchemas(json.getStringMap("result"));
    }

  }

  public static class KeyCertBytes extends MgmtResponse {

    private final byte[] key;

    private final byte[] cert;

    public KeyCertBytes(byte[] key, byte[] cert) {
      this.key = key;
      this.cert = cert;
    }

    public byte[] key() {
      return key;
    }

    public byte[] cert() {
      return cert;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("key", key);
      ret.put("cert", cert);
      return ret;
    }

    public static KeyCertBytes parse(JsonMap json) throws CodecException {
      return new KeyCertBytes(
          json.getBytes("key"), json.getBytes("cert"));
    }

  }

  public static class ByteArray extends MgmtResponse {

    private final byte[] result;

    public ByteArray(byte[] result) {
      this.result = result;
    }

    public byte[] result() {
      return result;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("result", result);
      return ret;
    }

    public static ByteArray parse(JsonMap json) throws CodecException {
      return new ByteArray(json.getBytes("result"));
    }

  } // class ByteArray

  public static class GetCa extends MgmtResponse {

    private final CaEntry result;

    public GetCa(CaEntry result) {
      this.result = Args.notNull(result, "result");
    }

    public CaEntry result() {
      return result;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("result", result);
      return ret;
    }

    public static GetCa parse(JsonMap json) throws CodecException {
      return new GetCa(CaEntry.parse(json.getNnMap("result")));
    }

  } // class GetCa

  public static class GetCaSystemStatus extends MgmtResponse {

    private final CaSystemStatus result;

    public GetCaSystemStatus(CaSystemStatus result) {
      this.result = Args.notNull(result, "result");
    }

    public CaSystemStatus result() {
      return result;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.putEnum("result", result);
      return ret;
    }

    public static GetCaSystemStatus parse(JsonMap json) throws CodecException {
      return new GetCaSystemStatus(CaSystemStatus.valueOf(
          json.getNnString("result")));
    }

  } // class GetCaSystemStatus

  public static class GetCertprofile extends MgmtResponse {

    private final CertprofileEntry result;

    public GetCertprofile(CertprofileEntry result) {
      this.result = Args.notNull(result, "result");
    }

    public CertprofileEntry result() {
      return result;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("result", result);
      return ret;
    }

    public static GetCertprofile parse(JsonMap json) throws CodecException {
      return new GetCertprofile(CertprofileEntry.parse(
          json.getNnMap("result")));
    }

  } // class GetCertprofile

  public static class GetCert extends MgmtResponse {

    private final X509Cert cert;

    private final CertRevocationInfo revInfo;

    private final String certprofile;

    public GetCert(X509Cert cert, CertRevocationInfo revInfo,
                   String certprofile) {
      this.cert = cert;
      this.revInfo = revInfo;
      this.certprofile = certprofile;
    }

    public X509Cert cert() {
      return cert;
    }

    public CertRevocationInfo revInfo() {
      return revInfo;
    }

    public String certprofile() {
      return certprofile;
    }

    public CertWithRevocationInfo toCertWithRevocationInfo() {
      if (cert == null) {
        return null;
      }

      CertWithRevocationInfo ret = new CertWithRevocationInfo();
      ret.setCert(new CertWithDbId(cert));
      ret.setCertprofile(certprofile);
      ret.setRevInfo(revInfo);
      return ret;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      if (cert != null) {
        ret.put("cert", cert.getEncoded());
      }
      ret.put("certprofile", certprofile);
      ret.put("revInfo", revInfo);
      return ret;
    }

    public static GetCert parse(JsonMap json) throws CodecException {
      byte[] bytes = json.getBytes("cert");
      if (bytes == null) {
        return new GetCert(null, null, null);
      }

      X509Cert cert;
      try {
        cert = X509Util.parseCert(bytes);
      } catch (CertificateEncodingException e) {
        throw new CodecException(e);
      }

      JsonMap map = json.getMap("revInfo");
      CertRevocationInfo revInfo = null;
      if (map != null) {
        revInfo = CertRevocationInfo.parse(json);
      }
      return new GetCert(cert, revInfo, json.getString("certprofile"));
    }

  } // class GetCert

  public static class GetKeypairGen extends MgmtResponse {

    private final KeypairGenEntry result;

    public GetKeypairGen(KeypairGenEntry result) {
      this.result = Args.notNull(result, "result");
    }

    public KeypairGenEntry result() {
      return result;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("result", result);
      return ret;
    }

    public static GetKeypairGen parse(JsonMap json) throws CodecException {
      return new GetKeypairGen(KeypairGenEntry.parse(
          json.getNnMap("result")));
    }

  } // class GetCertprofile

  public static class GetPublisher extends MgmtResponse {

    private final PublisherEntry result;

    public GetPublisher(PublisherEntry result) {
      this.result = Args.notNull(result, "result");
    }

    public PublisherEntry result() {
      return result;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("result", result);
      return ret;
    }

    public static GetPublisher parse(JsonMap json) throws CodecException {
      return new GetPublisher(PublisherEntry.parse(
          json.getNnMap("result")));
    }

  } // class GetPublisher

  public static class GetRequestor extends MgmtResponse {

    private final RequestorEntry result;

    public GetRequestor(RequestorEntry result) {
      this.result = Args.notNull(result, "result");
    }

    public RequestorEntry result() {
      return result;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("result", result);
      return ret;
    }

    public static GetRequestor parse(JsonMap json) throws CodecException {
      return new GetRequestor(RequestorEntry.parse(
          json.getNnMap("result")));
    }

  } // class GetRequestor

  public static class GetRequestorsForCa extends MgmtResponse {

    private final Set<CaHasRequestorEntry> result;

    public GetRequestorsForCa(Set<CaHasRequestorEntry> result) {
      this.result = Args.notNull(result, "result");
    }

    public Set<CaHasRequestorEntry> result() {
      return result;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      JsonList list = new JsonList();
      ret.put("result", list);
      for (CaHasRequestorEntry v : result) {
        list.add(v.toCodec());
      }
      return ret;
    }

    public static GetRequestorsForCa parse(JsonMap json)
        throws CodecException {
      JsonList list = json.getNnList("result");

      Set<CaHasRequestorEntry> entries = new HashSet<>();
      for (JsonMap v : list.toMapList()) {
        entries.add(CaHasRequestorEntry.parse(v));
      }
      return new GetRequestorsForCa(entries);
    }

  } // class GetRequestorsForCa

  public static class GetSigner extends MgmtResponse {

    private final SignerEntry result;

    public GetSigner(SignerEntry result) {
      this.result = Args.notNull(result, "result");
    }

    public SignerEntry result() {
      return result;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("result", result);
      return ret;
    }

    public static GetSigner parse(JsonMap json) throws CodecException {
      return new GetSigner(SignerEntry.parse(json.getNnMap("result")));
    }

  } // class GetSigner

  public static class ListCertificates extends MgmtResponse {

    private final List<CertListInfo> result;

    public ListCertificates(List<CertListInfo> result) {
      this.result = Args.notNull(result, "result");
    }

    public List<CertListInfo> result() {
      return result;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.putEncodables("result", result);
      return ret;
    }

    public static ListCertificates parse(JsonMap json) throws CodecException {
      JsonList list = json.getNnList("result");
      List<CertListInfo> certs = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        certs.add(CertListInfo.parse(v));
      }
      return new ListCertificates(certs);
    }

  } // class ListCertificates

  public static class StringResponse extends MgmtResponse {

    private final String result;

    public StringResponse(String result) {
      this.result = Args.notNull(result, "result");
    }

    public String result() {
      return result;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("result", result);
      return ret;
    }

    public static StringResponse parse(JsonMap json) throws CodecException {
      return new StringResponse(json.getNnString("result"));
    }

  } // class StringResponse

  public static class StringSet extends MgmtResponse {

    private final Set<String> result;

    public StringSet(Set<String> result) {
      this.result = Args.notNull(result, "result");
    }

    public Set<String> result() {
      return result;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.putStrings("result", result);
      return ret;
    }

    public static StringSet parse(JsonMap json) throws CodecException {
      return new StringSet(json.getNnStringSet("result"));
    }

  } // class StringSet

}
