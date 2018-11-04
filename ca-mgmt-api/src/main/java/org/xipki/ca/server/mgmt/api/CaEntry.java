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

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeyUsage;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.CompareUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;

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

  private ScepControl scepControl;

  private CrlControl crlControl;

  private String crlSignerName;

  private CmpControl cmpControl;

  private String cmpResponderName;

  private String scepResponderName;

  private boolean duplicateKeyPermitted;

  private boolean duplicateSubjectPermitted;

  private ProtocolSupport protocolSupport;

  private boolean saveRequest;

  private ValidityMode validityMode = ValidityMode.STRICT;

  private int permission;

  private int expirationPeriod;

  private int keepExpiredCertInDays;

  private ConfPairs extraControl;

  private CaUris caUris;

  private X509Certificate cert;

  private int serialNoBitLen;

  private long nextCrlNumber;

  private int numCrls;

  private CertRevocationInfo revocationInfo;

  private String subject;

  private String hexSha1OfCert;

  // For the deserialization only
  @SuppressWarnings("unused")
  private CaEntry() {
  }

  public CaEntry(NameId ident, int serialNoBitLen, long nextCrlNumber, String signerType,
      String signerConf, CaUris caUris, int numCrls, int expirationPeriod) {
    this.ident = ParamUtil.requireNonNull("ident", ident);
    this.signerType = ParamUtil.requireNonBlankLower("signerType", signerType);
    this.expirationPeriod = ParamUtil.requireMin("expirationPeriod", expirationPeriod, 0);
    this.signerConf = ParamUtil.requireNonBlank("signerConf", signerConf);

    this.numCrls = ParamUtil.requireMin("numCrls", numCrls, 1);
    this.serialNoBitLen = ParamUtil.requireRange("serialNoBitLen", serialNoBitLen, 63, 159);
    this.nextCrlNumber = ParamUtil.requireMin("nextCrlNumber", nextCrlNumber, 1);
    this.caUris = (caUris == null) ? CaUris.EMPTY_INSTANCE : caUris;
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

  public void setCmpControl(CmpControl cmpControl) {
    this.cmpControl = cmpControl;
  }

  public CmpControl getCmpControl() {
    return cmpControl;
  }

  public void setCrlControl(CrlControl crlControl) {
    this.crlControl = crlControl;
  }

  public CrlControl getCrlControl() {
    return crlControl;
  }

  public void setScepControl(ScepControl scepControl) {
    this.scepControl = scepControl;
  }

  public ScepControl getScepControl() {
    return scepControl;
  }

  public String getCmpResponderName() {
    return cmpResponderName;
  }

  public void setCmpResponderName(String cmpResponderName) {
    this.cmpResponderName = (cmpResponderName == null) ? null : cmpResponderName.toLowerCase();
  }

  public String getScepResponderName() {
    return scepResponderName;
  }

  public void setScepResponderName(String scepResponderName) {
    this.scepResponderName = (scepResponderName == null) ? null : scepResponderName.toLowerCase();
  }

  public String getCrlSignerName() {
    return crlSignerName;
  }

  public void setCrlSignerName(String crlSignerName) {
    this.crlSignerName = (crlSignerName == null) ? null : crlSignerName.toLowerCase();
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

  public ProtocolSupport getProtocoSupport() {
    return protocolSupport;
  }

  public void setProtocolSupport(ProtocolSupport protocolSupport) {
    this.protocolSupport = protocolSupport;
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
      revInfoText = StringUtil.concatObjectsCap(30,
          "\n\treason: ", revocationInfo.getReason().getDescription(),
          "\n\trevoked at ", revocationInfo.getRevocationTime());
    }

    return StringUtil.concatObjectsCap(1500,
        "id: ", ident.getId(), "\nname: ", ident.getName(),
        "\nstatus: ", (status == null ? "null" : status.getStatus()),
        "\nmax. validity: ", maxValidity,
        "\nexpiration period: ", expirationPeriod, " days",
        "\nsigner type: ", signerType,
        "\nsigner conf: ", (signerConf == null ? "null" :
          InternUtil.signerConfToString(signerConf, verbose, ignoreSensitiveInfo)),
        "\nCMP control:\n", (cmpControl == null ? "  null" : cmpControl.toString(verbose)),
        "\nCRL control:\n", (crlControl == null ? "  null" : crlControl.toString(verbose)),
        "\nSCEP control: \n", (scepControl == null ? "  null" : scepControl.toString(verbose)),
        "\nCMP responder name: ", cmpResponderName,
        "\nSCEP responder name: ", scepResponderName,
        "\nCRL signer name: ", crlSignerName,
        "\nduplicate key: ", duplicateKeyPermitted,
        "\nduplicate subject: ", duplicateSubjectPermitted,
        "\n", protocolSupport,
        "\nsave request: ", saveRequest,
        "\nvalidity mode: ", validityMode,
        "\npermission: ", PermissionConstants.permissionToString(permission),
        "\nkeep expired certs: ",
            (keepExpiredCertInDays < 0 ? "forever" : keepExpiredCertInDays + " days"),
        "\nextra control: ", extraCtrlText,
        "\nserial number bit length: ", serialNoBitLen,
        "\nnext CRl number: ", nextCrlNumber,
        "\n", caUris, "\ncert: \n", InternUtil.formatCert(cert, verbose),
        "\nrevocation: ", (revocationInfo == null ? "not revoked" : "revoked"), revInfoText);
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
    if (this == obj) {
      return true;
    } else if (!(obj instanceof CaEntry)) {
      return false;
    }

    return equals((CaEntry) obj, false, false);
  }

  public boolean equals(CaEntry obj, boolean ignoreDynamicFields, boolean ignoreId) {
    if (!ignoreDynamicFields) {
      if (nextCrlNumber != obj.nextCrlNumber) {
        return false;
      }
    }

    return ident.equals(obj.ident, ignoreId)
      && signerType.equals(obj.signerType)
      && CompareUtil.equalsObject(status, obj.status)
      && CompareUtil.equalsObject(protocolSupport, obj.protocolSupport)
      && CompareUtil.equalsObject(maxValidity, obj.maxValidity)
      && CompareUtil.equalsObject(cmpControl, obj.cmpControl)
      && CompareUtil.equalsObject(crlControl, obj.crlControl)
      && CompareUtil.equalsObject(scepControl, obj.scepControl)
      && CompareUtil.equalsObject(cmpResponderName, obj.cmpResponderName)
      && CompareUtil.equalsObject(scepResponderName, obj.scepResponderName)
      && CompareUtil.equalsObject(crlSignerName, obj.crlSignerName)
      && (duplicateKeyPermitted == obj.duplicateKeyPermitted)
      && (duplicateSubjectPermitted == obj.duplicateSubjectPermitted)
      && (saveRequest == obj.saveRequest)
      && CompareUtil.equalsObject(validityMode, obj.validityMode)
      && (permission == obj.permission)
      && (expirationPeriod == obj.expirationPeriod)
      && (keepExpiredCertInDays == obj.keepExpiredCertInDays)
      && CompareUtil.equalsObject(extraControl, obj.extraControl)
      && CompareUtil.equalsObject(caUris, obj.caUris)
      && CompareUtil.equalsObject(cert, obj.cert)
      && (serialNoBitLen == obj.serialNoBitLen)
      && (numCrls == obj.numCrls)
      && CompareUtil.equalsObject(revocationInfo, obj.revocationInfo);
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

  public CaUris getCaUris() {
    return caUris;
  }

  public X509Certificate getCert() {
    return cert;
  }

  public int getNumCrls() {
    return numCrls;
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

}
