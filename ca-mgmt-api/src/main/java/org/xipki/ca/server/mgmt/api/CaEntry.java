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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.xipki.ca.api.NameId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.security.SignerConf;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;

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

  public CaEntry(NameId ident, String signerType, String signerConf, int expirationPeriod)
      throws CaMgmtException {
    this.ident = ParamUtil.requireNonNull("ident", ident);
    this.signerType = ParamUtil.requireNonBlank("signerType", signerType);
    this.expirationPeriod = ParamUtil.requireMin("expirationPeriod", expirationPeriod, 0);
    this.signerConf = ParamUtil.requireNonBlank("signerConf", signerConf);
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

    return StringUtil.concatObjectsCap(500, "id: ", ident.getId(), "\nname: ", ident.getName(),
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
        "\nextraControl: ", extraCtrlText, "\n");
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

    return equals((CaEntry) obj);
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

    return true;
  }

  @Override
  public int hashCode() {
    return ident.hashCode();
  }

}
