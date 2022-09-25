/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.api.mgmt;

import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.mgmt.entry.*;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.util.X509Util;

import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CA Management response via the REST API.
 *
 * @author Lijun Liao
 */

public abstract class MgmtResponse extends MgmtMessage {

  public static class GetDbSchemas extends MgmtResponse {

    private Map<String, String> result;

    public GetDbSchemas() {
    }

    public GetDbSchemas(Map<String, String> result) {
      this.result = result;
    }

    public Map<String, String> getResult() {
      return result;
    }

    public void setResult(Map<String, String> result) {
      this.result = result;
    }

  }

  public static class CertWithDbIdWrapper {

    private byte[] cert;

    private Long certId;

    public CertWithDbIdWrapper() {
    }

    public CertWithDbIdWrapper(CertWithDbId certWithDbId) {
      this.cert = certWithDbId.getCert().getEncoded();
      this.certId = certWithDbId.getCertId();
    }

    public byte[] getCert() {
      return cert;
    }

    public void setCert(byte[] cert) {
      this.cert = cert;
    }

    public Long getCertId() {
      return certId;
    }

    public void setCertId(Long certId) {
      this.certId = certId;
    }

    public CertWithDbId toCertWithDbId() throws CertificateException {
      CertWithDbId ret = new CertWithDbId(X509Util.parseCert(cert));
      ret.setCertId(certId);
      return ret;
    }
  } // class CertWithDbIdWrapper

  public static class CertWithRevocationInfoWrapper {

    private CertWithDbIdWrapper cert;

    private CertRevocationInfo revInfo;

    private String certprofile;

    public CertWithRevocationInfoWrapper() {
    }

    public CertWithRevocationInfoWrapper(CertWithRevocationInfo info) {
      this.cert = new CertWithDbIdWrapper(info.getCert());
      this.revInfo = info.getRevInfo();
      this.certprofile = info.getCertprofile();
    }

    public CertWithDbIdWrapper getCert() {
      return cert;
    }

    public void setCert(CertWithDbIdWrapper cert) {
      this.cert = cert;
    }

    public CertRevocationInfo getRevInfo() {
      return revInfo;
    }

    public void setRevInfo(CertRevocationInfo revInfo) {
      this.revInfo = revInfo;
    }

    public String getCertprofile() {
      return certprofile;
    }

    public void setCertprofile(String certprofile) {
      this.certprofile = certprofile;
    }

    public CertWithRevocationInfo toCertWithRevocationInfo() throws CertificateException {
      CertWithRevocationInfo ret = new CertWithRevocationInfo();
      ret.setCert(cert.toCertWithDbId());
      ret.setCertprofile(certprofile);
      ret.setRevInfo(revInfo);
      return ret;
    }

  } // class CertWithRevocationInfoWrapper

  public static class KeyCertBytes extends MgmtResponse {

    private byte[] key;

    private byte[] cert;

    public KeyCertBytes() {
    }

    public KeyCertBytes(byte[] key, byte[] cert) {
      this.key = key;
      this.cert = cert;
    }

    public byte[] getKey() {
      return key;
    }

    public void setKey(byte[] key) {
      this.key = key;
    }

    public byte[] getCert() {
      return cert;
    }

    public void setCert(byte[] cert) {
      this.cert = cert;
    }
  } // class ByteArray

  public static class ByteArray extends MgmtResponse {

    private byte[] result;

    public ByteArray() {
    }

    public ByteArray(byte[] result) {
      this.result = result;
    }

    public byte[] getResult() {
      return result;
    }

    public void setResult(byte[] result) {
      this.result = result;
    }

  } // class ByteArray

  public static class Error extends MgmtResponse {

    private String message;

    public Error() {
    }

    public Error(String message) {
      this.message = message;
    }

    public String getMessage() {
      return message;
    }

    public void setMessage(String message) {
      this.message = message;
    }

  } // class Error

  public static class GetCa extends MgmtResponse {

    private CaEntryWrapper result;

    public GetCa() {
    }

    public GetCa(CaEntryWrapper result) {
      this.result = result;
    }

    public CaEntryWrapper getResult() {
      return result;
    }

    public void setResult(CaEntryWrapper result) {
      this.result = result;
    }

  } // class GetCa

  public static class GetCaSystemStatus extends MgmtResponse {

    private CaSystemStatus result;

    public GetCaSystemStatus() {
    }

    public GetCaSystemStatus(CaSystemStatus result) {
      this.result = result;
    }

    public CaSystemStatus getResult() {
      return result;
    }

    public void setResult(CaSystemStatus result) {
      this.result = result;
    }

  } // class GetCaSystemStatus

  public static class GetCertprofile extends MgmtResponse {

    private CertprofileEntry result;

    public GetCertprofile() {
    }

    public GetCertprofile(CertprofileEntry result) {
      this.result = result;
    }

    public CertprofileEntry getResult() {
      return result;
    }

    public void setResult(CertprofileEntry result) {
      this.result = result;
    }

  } // class GetCertprofile

  public static class GetCert extends MgmtResponse {

    private CertWithRevocationInfoWrapper result;

    public GetCert() {
    }

    public GetCert(CertWithRevocationInfoWrapper result) {
      this.result = result;
    }

    public CertWithRevocationInfoWrapper getResult() {
      return result;
    }

    public void setResult(CertWithRevocationInfoWrapper result) {
      this.result = result;
    }

  } // class GetCert

  public static class GetKeypairGen extends MgmtResponse {

    private KeypairGenEntry result;

    public GetKeypairGen() {
    }

    public GetKeypairGen(KeypairGenEntry result) {
      this.result = result;
    }

    public KeypairGenEntry getResult() {
      return result;
    }

    public void setResult(KeypairGenEntry result) {
      this.result = result;
    }

  } // class GetCertprofile

  public static class GetPublischersForCa extends MgmtResponse {

    private List<PublisherEntry> result;

    public GetPublischersForCa() {
    }

    public GetPublischersForCa(List<PublisherEntry> result) {
      this.result = result;
    }

    public List<PublisherEntry> getResult() {
      return result;
    }

    public void setResult(List<PublisherEntry> result) {
      this.result = result;
    }

  } // class GetPublischersForCa

  public static class GetPublisher extends MgmtResponse {

    private PublisherEntry result;

    public GetPublisher() {
    }

    public GetPublisher(PublisherEntry result) {
      this.result = result;
    }

    public PublisherEntry getResult() {
      return result;
    }

    public void setResult(PublisherEntry result) {
      this.result = result;
    }

  } // class GetPublisher

  public static class GetRequestor extends MgmtResponse {

    private RequestorEntry result;

    public GetRequestor() {
    }

    public GetRequestor(RequestorEntry result) {
      this.result = result;
    }

    public RequestorEntry getResult() {
      return result;
    }

    public void setResult(RequestorEntry result) {
      this.result = result;
    }

  } // class GetRequestor

  public static class GetRequestorsForCa extends MgmtResponse {

    private Set<CaHasRequestorEntry> result;

    public GetRequestorsForCa() {
    }

    public GetRequestorsForCa(Set<CaHasRequestorEntry> result) {
      this.result = result;
    }

    public Set<CaHasRequestorEntry> getResult() {
      return result;
    }

    public void setResult(Set<CaHasRequestorEntry> result) {
      this.result = result;
    }

  } // class GetRequestorsForCa

  public static class GetSigner extends MgmtResponse {

    private SignerEntryWrapper result;

    public GetSigner() {
    }

    public GetSigner(SignerEntryWrapper result) {
      this.result = result;
    }

    public SignerEntryWrapper getResult() {
      return result;
    }

    public void setResult(SignerEntryWrapper result) {
      this.result = result;
    }

  } // class GetSigner

  public static class ListCertificates extends MgmtResponse {

    private List<CertListInfo> result;

    public ListCertificates() {
    }

    public ListCertificates(List<CertListInfo> result) {
      this.result = result;
    }

    public List<CertListInfo> getResult() {
      return result;
    }

    public void setResult(List<CertListInfo> result) {
      this.result = result;
    }

  } // class ListCertificates

  public static class LoadConf extends MgmtResponse {

    private Map<String, byte[]> result;

    public LoadConf() {
    }

    public LoadConf(Map<String, byte[]> result) {
      this.result = result;
    }

    public Map<String, byte[]> getResult() {
      return result;
    }

    public void setResult(Map<String, byte[]> result) {
      this.result = result;
    }

  } // class LoadConf

  public static class StringResponse extends MgmtResponse {

    private String result;

    public StringResponse() {
    }

    public StringResponse(String result) {
      this.result = result;
    }

    public String getResult() {
      return result;
    }

    public void setResult(String result) {
      this.result = result;
    }

  } // class StringResponse

  public static class StringSet extends MgmtResponse {

    private Set<String> result;

    public StringSet() {
    }

    public StringSet(Set<String> result) {
      this.result = result;
    }

    public Set<String> getResult() {
      return result;
    }

    public void setResult(Set<String> result) {
      this.result = result;
    }

  } // class StringSet

}
