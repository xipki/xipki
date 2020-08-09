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

import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xipki.ca.api.CertWithDbId;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.util.X509Util;

/**
 * CA Management response via the REST API.
 *
 * @author Lijun Liao
 */

public abstract class MgmtResponse extends MgmtMessage {

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

    public CertWithDbId toCertWithDbId()
        throws CertificateException {
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

    public CertWithRevocationInfo toCertWithRevocationInfo()
        throws CertificateException {
      CertWithRevocationInfo ret = new CertWithRevocationInfo();
      ret.setCert(cert.toCertWithDbId());
      ret.setCertprofile(certprofile);
      ret.setRevInfo(revInfo);
      return ret;
    }

  } // class CertWithRevocationInfoWrapper

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

  public static class GetAliasesForCa extends MgmtResponse {

    private Set<String> result;

    public GetAliasesForCa() {
    }

    public GetAliasesForCa(Set<String> result) {
      this.result = result;
    }

    public Set<String> getResult() {
      return result;
    }

    public void setResult(Set<String> result) {
      this.result = result;
    }

  } // class GetAliasesForCa

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

  public static class GetCaHasUserForUser extends MgmtResponse {

    private Map<String, MgmtEntry.CaHasUser> result;

    public GetCaHasUserForUser() {
    }

    public GetCaHasUserForUser(Map<String, MgmtEntry.CaHasUser> result) {
      this.result = result;
    }

    public Map<String, MgmtEntry.CaHasUser> getResult() {
      return result;
    }

    public void setResult(Map<String, MgmtEntry.CaHasUser> result) {
      this.result = result;
    }

  } // class GetCaHasUserForUser

  public static class GetCaHasUsersForUser extends MgmtResponse {

    private Map<String, MgmtEntry.CaHasUser> result;

    public GetCaHasUsersForUser() {
    }

    public GetCaHasUsersForUser(Map<String, MgmtEntry.CaHasUser> result) {
      this.result = result;
    }

    public Map<String, MgmtEntry.CaHasUser> getResult() {
      return result;
    }

    public void setResult(Map<String, MgmtEntry.CaHasUser> result) {
      this.result = result;
    }

  } // class GetCaHasUsersForUser

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

    private MgmtEntry.Certprofile result;

    public GetCertprofile() {
    }

    public GetCertprofile(MgmtEntry.Certprofile result) {
      this.result = result;
    }

    public MgmtEntry.Certprofile getResult() {
      return result;
    }

    public void setResult(MgmtEntry.Certprofile result) {
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

  public static class GetPublischersForCa extends MgmtResponse {

    private List<MgmtEntry.Publisher> result;

    public GetPublischersForCa() {
    }

    public GetPublischersForCa(List<MgmtEntry.Publisher> result) {
      this.result = result;
    }

    public List<MgmtEntry.Publisher> getResult() {
      return result;
    }

    public void setResult(List<MgmtEntry.Publisher> result) {
      this.result = result;
    }

  } // class GetPublischersForCa

  public static class GetPublisher extends MgmtResponse {

    private MgmtEntry.Publisher result;

    public GetPublisher() {
    }

    public GetPublisher(MgmtEntry.Publisher result) {
      this.result = result;
    }

    public MgmtEntry.Publisher getResult() {
      return result;
    }

    public void setResult(MgmtEntry.Publisher result) {
      this.result = result;
    }

  } // class GetPublisher

  public static class GetRequestor extends MgmtResponse {

    private MgmtEntry.Requestor result;

    public GetRequestor() {
    }

    public GetRequestor(MgmtEntry.Requestor result) {
      this.result = result;
    }

    public MgmtEntry.Requestor getResult() {
      return result;
    }

    public void setResult(MgmtEntry.Requestor result) {
      this.result = result;
    }

  } // class GetRequestor

  public static class GetRequestorsForCa extends MgmtResponse {

    private Set<MgmtEntry.CaHasRequestor> result;

    public GetRequestorsForCa() {
    }

    public GetRequestorsForCa(Set<MgmtEntry.CaHasRequestor> result) {
      this.result = result;
    }

    public Set<MgmtEntry.CaHasRequestor> getResult() {
      return result;
    }

    public void setResult(Set<MgmtEntry.CaHasRequestor> result) {
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

  public static class GetUser extends MgmtResponse {

    private MgmtEntry.User result;

    public GetUser() {
    }

    public GetUser(MgmtEntry.User result) {
      this.result = result;
    }

    public MgmtEntry.User getResult() {
      return result;
    }

    public void setResult(MgmtEntry.User result) {
      this.result = result;
    }

  } // class GetUser

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
