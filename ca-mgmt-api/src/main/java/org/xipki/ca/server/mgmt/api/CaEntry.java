/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.server.mgmt.api;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.xipki.ca.api.NameId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeyUsage;
import org.xipki.security.SignerConf;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaEntry {

  private NameId ident;

  private CaStatus status;

  private CertValidity maxValidity;

  private String signerType;

  private String signerConf;

  private String cmpControlName;

  private String responderName;

  private boolean duplicateKeyPermitted;

  private boolean duplicateSubjectPermitted;

  private boolean saveRequest;

  private ValidityMode validityMode = ValidityMode.STRICT;

  private int permission;

  private int expirationPeriod;

  private int keepExpiredCertInDays;

  private ConfPairs extraControl;

  private List<String> crlUris;

  private List<String> deltaCrlUris;

  private List<String> ocspUris;

  private List<String> caCertUris;

  private X509Certificate cert;

  private String crlSignerName;

  private int serialNoBitLen;

  private long nextCrlNumber;

  private int numCrls;

  private CertRevocationInfo revocationInfo;

  private String subject;

  private String hexSha1OfCert;

  public CaEntry(NameId ident, int serialNoBitLen, long nextCrlNumber, String signerType,
      String signerConf, CaUris caUris, int numCrls, int expirationPeriod) throws CaMgmtException {
    this.ident = ParamUtil.requireNonNull("ident", ident);
    this.signerType = ParamUtil.requireNonBlank("signerType", signerType).toLowerCase();
    this.expirationPeriod = ParamUtil.requireMin("expirationPeriod", expirationPeriod, 0);
    this.signerConf = ParamUtil.requireNonBlank("signerConf", signerConf);

    this.numCrls = ParamUtil.requireMin("numCrls", numCrls, 1);
    this.serialNoBitLen = ParamUtil.requireRange("serialNoBitLen", serialNoBitLen, 63, 159);
    this.nextCrlNumber = ParamUtil.requireMin("nextCrlNumber", nextCrlNumber, 1);

    this.caCertUris = caUris.getCaCertUris();
    this.ocspUris = caUris.getOcspUris();
    this.crlUris = caUris.getCrlUris();
    this.deltaCrlUris = caUris.getDeltaCrlUris();
  }

  public static List<String[]> splitCaSignerConfs(String conf) throws XiSecurityException {
    ConfPairs pairs = new ConfPairs(conf);
    String str = pairs.value("algo");
    if (str == null) {
      throw new XiSecurityException("no algo is defined in CA signerConf");
    }

    List<String> list = StringUtil.split(str, ":");
    if (CollectionUtil.isEmpty(list)) {
      throw new XiSecurityException("empty algo is defined in CA signerConf");
    }

    List<String[]> signerConfs = new ArrayList<>(list.size());
    for (String n : list) {
      String c14nAlgo;
      try {
        c14nAlgo = AlgorithmUtil.canonicalizeSignatureAlgo(n);
      } catch (NoSuchAlgorithmException ex) {
        throw new XiSecurityException(ex.getMessage(), ex);
      }
      pairs.putPair("algo", c14nAlgo);
      signerConfs.add(new String[]{c14nAlgo, pairs.getEncoded()});
    }

    return signerConfs;
  }

  public NameId getIdent() {
    return ident;
  }

  public CertValidity getMaxValidity() {
    return maxValidity;
  }

  public void setMaxValidity(CertValidity maxValidity) {
    this.maxValidity = maxValidity;
  }

  public int getKeepExpiredCertInDays() {
    return keepExpiredCertInDays;
  }

  public void setKeepExpiredCertInDays(int days) {
    this.keepExpiredCertInDays = days;
  }

  public void setSignerConf(String signerConf) {
    this.signerConf = ParamUtil.requireNonBlank("signerConf", signerConf);
  }

  public String getSignerConf() {
    return signerConf;
  }

  public CaStatus getStatus() {
    return status;
  }

  public void setStatus(CaStatus status) {
    this.status = status;
  }

  public String getSignerType() {
    return signerType;
  }

  public void setCmpControlName(String cmpControlName) {
    this.cmpControlName = (cmpControlName == null) ? null : cmpControlName.toLowerCase();
  }

  public String getCmpControlName() {
    return cmpControlName;
  }

  public String getResponderName() {
    return responderName;
  }

  public void setResponderName(String responderName) {
    this.responderName = (responderName == null) ? null : responderName.toLowerCase();
  }

  public boolean isDuplicateKeyPermitted() {
    return duplicateKeyPermitted;
  }

  public void setDuplicateKeyPermitted(boolean duplicateKeyPermitted) {
    this.duplicateKeyPermitted = duplicateKeyPermitted;
  }

  public boolean isDuplicateSubjectPermitted() {
    return duplicateSubjectPermitted;
  }

  public void setDuplicateSubjectPermitted(boolean duplicateSubjectPermitted) {
    this.duplicateSubjectPermitted = duplicateSubjectPermitted;
  }

  public boolean isSaveRequest() {
    return saveRequest;
  }

  public void setSaveRequest(boolean saveRequest) {
    this.saveRequest = saveRequest;
  }

  public ValidityMode getValidityMode() {
    return validityMode;
  }

  public void setValidityMode(ValidityMode mode) {
    this.validityMode = ParamUtil.requireNonNull("mode", mode);
  }

  public int getPermission() {
    return permission;
  }

  public void setPermission(int permission) {
    this.permission = permission;
  }

  public int getExpirationPeriod() {
    return expirationPeriod;
  }

  public ConfPairs getExtraControl() {
    return extraControl;
  }

  public void setExtraControl(ConfPairs extraControl) {
    this.extraControl = extraControl;
  }

  @Override
  public String toString() {
    return toString(false);
  }

  public String toString(boolean verbose) {
    return toString(verbose, true);
  }

  public String toString(boolean verbose, boolean ignoreSensitiveInfo) {
    String extraCtrlText;
    if (extraControl == null) {
      extraCtrlText = "null";
    } else {
      extraCtrlText = extraControl.getEncoded();
      if (!verbose && extraCtrlText.length() > 100) {
        extraCtrlText = StringUtil.concat(extraCtrlText.substring(0, 97), "...");
      }
    }

    String revInfoText = "";
    if (revocationInfo != null) {
      StringUtil.concatObjectsCap(30,
          "\treason: ", revocationInfo.getReason().getDescription(),
          "\n\trevoked at ", revocationInfo.getRevocationTime(), "\n");
    }

    return StringUtil.concatObjectsCap(1500,
        "id: ", ident.getId(), "\nname: ", ident.getName(),
        "\nstatus: ", (status == null ? "null" : status.getStatus()),
        "\nmaxValidity: ", maxValidity,
        "\nexpirationPeriod: ", expirationPeriod, " days",
        "\nsignerType: ", signerType,
        "\nsignerConf: ", (signerConf == null ? "null" :
          SignerConf.toString(signerConf, verbose, ignoreSensitiveInfo)),
        "\ncmpcontrolName: ", cmpControlName,
        "\nresponderName: ", responderName,
        "\nduplicateKey: ", duplicateKeyPermitted,
        "\nduplicateSubject: ", duplicateSubjectPermitted,
        "\nsaveRequest: ", saveRequest,
        "\nvalidityMode: ", validityMode,
        "\npermission: ", permission,
        "\nkeepExpiredCerts: ", (keepExpiredCertInDays < 0
                      ? "forever" : keepExpiredCertInDays + " days"),
        "\nextraControl: ", extraCtrlText, "\n",
        "serialNoBitLen: ", serialNoBitLen, "\nnextCrlNumber: ", nextCrlNumber,
        "\ndeltaCrlUris:", formatUris(deltaCrlUris), "\ncrlUris:", formatUris(crlUris),
        "\nocspUris:", formatUris(ocspUris), "\ncaCertUris:", formatUris(caCertUris),
        "\ncert: \n", InternUtil.formatCert(cert, verbose),
        "\ncrlSignerName: ", crlSignerName,
        "\nrevocation: ", (revocationInfo == null ? "not revoked" : "revoked"), "\n",
        revInfoText);
  } // method toString

  protected static String urisToString(Collection<? extends Object> tokens) {
    if (CollectionUtil.isEmpty(tokens)) {
      return null;
    }

    StringBuilder sb = new StringBuilder();

    int size = tokens.size();
    int idx = 0;
    for (Object token : tokens) {
      sb.append(token);
      if (idx++ < size - 1) {
        sb.append(" ");
      }
    }
    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof CaEntry)) {
      return false;
    }

    return equals((CaEntry) obj, false, false);
  }

  public boolean equals(CaEntry obj, boolean ignoreDynamicFields, boolean ignoreId) {
    if (!ident.equals(obj.ident, ignoreId)) {
      return false;
    }

    if (!signerType.equals(obj.signerType)) {
      return false;
    }

    if (!CompareUtil.equalsObject(status, obj.status)) {
      return false;
    }

    if (!CompareUtil.equalsObject(maxValidity, obj.maxValidity)) {
      return false;
    }

    if (!CompareUtil.equalsObject(cmpControlName, obj.cmpControlName)) {
      return false;
    }

    if (!CompareUtil.equalsObject(responderName, obj.responderName)) {
      return false;
    }

    if (duplicateKeyPermitted != obj.duplicateKeyPermitted) {
      return false;
    }

    if (duplicateSubjectPermitted != obj.duplicateSubjectPermitted) {
      return false;
    }

    if (saveRequest != obj.saveRequest) {
      return false;
    }

    if (!CompareUtil.equalsObject(validityMode, obj.validityMode)) {
      return false;
    }

    if (permission != obj.permission) {
      return false;
    }

    if (expirationPeriod != obj.expirationPeriod) {
      return false;
    }

    if (keepExpiredCertInDays != obj.keepExpiredCertInDays) {
      return false;
    }

    if (!CompareUtil.equalsObject(extraControl, obj.extraControl)) {
      return false;
    }

    if (!ignoreDynamicFields) {
      if (nextCrlNumber != obj.nextCrlNumber) {
        return false;
      }
    }

    if (!CompareUtil.equalsObject(crlUris, obj.crlUris)) {
      return false;
    }

    if (!CompareUtil.equalsObject(deltaCrlUris, obj.deltaCrlUris)) {
      return false;
    }

    if (!CompareUtil.equalsObject(ocspUris, obj.ocspUris)) {
      return false;
    }

    if (!CompareUtil.equalsObject(caCertUris, obj.caCertUris)) {
      return false;
    }

    if (!CompareUtil.equalsObject(cert, obj.cert)) {
      return false;
    }

    if (!CompareUtil.equalsObject(crlSignerName, obj.crlSignerName)) {
      return false;
    }

    if (serialNoBitLen != obj.serialNoBitLen) {
      return false;
    }

    if (numCrls != obj.numCrls) {
      return false;
    }

    if (!CompareUtil.equalsObject(revocationInfo, obj.revocationInfo)) {
      return false;
    }
    return true;
  }

  @Override
  public int hashCode() {
    return ident.hashCode();
  }

  public void setCert(X509Certificate cert) throws CaMgmtException {
    if (cert == null) {
      this.cert = null;
      this.subject = null;
      this.hexSha1OfCert = null;
    } else {
      if (!X509Util.hasKeyusage(cert, KeyUsage.keyCertSign)) {
        throw new CaMgmtException("CA certificate does not have keyusage keyCertSign");
      }
      this.cert = cert;
      this.subject = X509Util.getRfc4519Name(cert.getSubjectX500Principal());
      byte[] encodedCert;
      try {
        encodedCert = cert.getEncoded();
      } catch (CertificateEncodingException ex) {
        throw new CaMgmtException("could not encoded certificate", ex);
      }
      this.hexSha1OfCert = HashAlgo.SHA1.hexHash(encodedCert);
    }
  }

  public int getSerialNoBitLen() {
    return serialNoBitLen;
  }

  public void setSerialNoBitLen(int serialNoBitLen) {
    this.serialNoBitLen = ParamUtil.requireMin("serialNoBitLen", serialNoBitLen, 63);
  }

  public long getNextCrlNumber() {
    return nextCrlNumber;
  }

  public void setNextCrlNumber(long crlNumber) {
    this.nextCrlNumber = crlNumber;
  }

  public List<String> getCrlUris() {
    return crlUris;
  }

  public String getCrlUrisAsString() {
    return urisToString(crlUris);
  }

  public List<String> getDeltaCrlUris() {
    return deltaCrlUris;
  }

  public String getDeltaCrlUrisAsString() {
    return urisToString(deltaCrlUris);
  }

  public List<String> getOcspUris() {
    return ocspUris;
  }

  public String getOcspUrisAsString() {
    return urisToString(ocspUris);
  }

  public List<String> getCaCertUris() {
    return caCertUris;
  }

  public String getCaCertUrisAsString() {
    return urisToString(caCertUris);
  }

  public X509Certificate getCert() {
    return cert;
  }

  public int getNumCrls() {
    return numCrls;
  }

  public String getCrlSignerName() {
    return crlSignerName;
  }

  public void setCrlSignerName(String crlSignerName) {
    this.crlSignerName = (crlSignerName == null) ? null : crlSignerName.toLowerCase();
  }

  public CertRevocationInfo getRevocationInfo() {
    return revocationInfo;
  }

  public void setRevocationInfo(CertRevocationInfo revocationInfo) {
    this.revocationInfo = revocationInfo;
  }

  public Date getCrlBaseTime() {
    return (cert == null) ? null : cert.getNotBefore();
  }

  public String getSubject() {
    return subject;
  }

  public String getHexSha1OfCert() {
    return hexSha1OfCert;
  }

  private static String formatUris(List<String> uris) {
    if (CollectionUtil.isEmpty(uris)) {
      return "";
    }
    StringBuilder sb = new StringBuilder();
    for (String uri : uris) {
      sb.append("\n    ").append(uri);
    }
    return sb.toString();
  }

}
