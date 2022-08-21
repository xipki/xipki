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

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.*;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Management Entry CA.
 * @author Lijun Liao
 *
 */

public class CaEntry extends MgmtEntry {

  public static class CaSignerConf {

    private final SignAlgo algo;

    private final String conf;

    private CaSignerConf(SignAlgo algo, String conf) {
      this.algo = algo;
      this.conf = conf;
    }

    public SignAlgo getAlgo() {
      return algo;
    }

    public String getConf() {
      return conf;
    }

  }

  private NameId ident;

  private CaStatus status;

  private Validity maxValidity;

  private String signerType;

  private String signerConf;

  private CrlControl crlControl;

  private String crlSignerName;

  private CtlogControl ctlogControl;

  private RevokeSuspendedControl revokeSuspendedControl;

  private List<String> keypairGenNames;

  private boolean saveRequest;

  private boolean saveKeypair;

  private boolean saveCert = true;

  private ValidityMode validityMode = ValidityMode.STRICT;

  private int permission;

  private int expirationPeriod;

  private int keepExpiredCertInDays;

  private ConfPairs extraControl;

  private CaUris caUris;

  private X509Cert cert;

  private int pathLenConstraint;

  /**
   * certificate chain without the certificate specified in {@code #cert}. The first one issued
   * {@code #cert}, the second one issues the first one, and so on.
   */
  private List<X509Cert> certchain;

  private int serialNoLen;

  private long nextCrlNumber;

  private int numCrls;

  private CertRevocationInfo revocationInfo;

  private String subject;

  private String hexSha1OfCert;

  // For the deserialization only
  @SuppressWarnings("unused")
  private CaEntry() {
  }

  public CaEntry(NameId ident, int serialNoLen, long nextCrlNumber, String signerType,
      String signerConf, CaUris caUris, int numCrls, int expirationPeriod) {
    this.ident = Args.notNull(ident, "ident");
    this.signerType = Args.toNonBlankLower(signerType, "signerType");
    this.expirationPeriod = Args.notNegative(expirationPeriod, "expirationPeriod");
    this.signerConf = Args.notBlank(signerConf, "signerConf");

    this.numCrls = Args.positive(numCrls, "numCrls");
    this.serialNoLen = Args.range(serialNoLen, "serialNoLen",
        CaManager.MIN_SERIALNUMBER_SIZE, CaManager.MAX_SERIALNUMBER_SIZE);
    this.nextCrlNumber = Args.positive(nextCrlNumber, "nextCrlNumber");
    this.caUris = (caUris == null) ? CaUris.EMPTY_INSTANCE : caUris;
  } // constructor Ca

  @Override
  public CaEntry clone() {
    CaEntry ret = new CaEntry();
    ret.ident = ident;
    ret.serialNoLen = serialNoLen;
    ret.nextCrlNumber = nextCrlNumber;
    ret.signerType = signerType;
    ret.signerConf = signerConf;
    ret.caUris = caUris;
    ret.numCrls = numCrls;
    ret.expirationPeriod = expirationPeriod;
    ret.status = status;
    ret.maxValidity = maxValidity;
    ret.crlControl = crlControl;
    ret.crlSignerName = crlSignerName;
    ret.ctlogControl = ctlogControl;
    ret.revokeSuspendedControl = revokeSuspendedControl;
    ret.keypairGenNames = keypairGenNames;
    ret.saveRequest = saveRequest;
    ret.saveKeypair = saveKeypair;
    ret.saveCert = saveCert;
    ret.validityMode = validityMode;
    ret.permission = permission;
    ret.keepExpiredCertInDays = keepExpiredCertInDays;
    ret.extraControl = extraControl;
    ret.pathLenConstraint = pathLenConstraint;
    ret.revocationInfo = revocationInfo;
    ret.cert = cert;
    ret.certchain = certchain;
    ret.subject = subject;
    ret.hexSha1OfCert = hexSha1OfCert;
    return ret;
  }

  public static List<CaSignerConf> splitCaSignerConfs(String conf)
      throws XiSecurityException {
    ConfPairs pairs = new ConfPairs(conf);
    String str = pairs.value("algo");
    if (str == null) {
      throw new XiSecurityException("no algo is defined in CA signerConf");
    }

    List<String> list = StringUtil.split(str, ":");
    if (CollectionUtil.isEmpty(list)) {
      throw new XiSecurityException("empty algo is defined in CA signerConf");
    }

    List<CaSignerConf> signerConfs = new ArrayList<>(list.size());
    for (String n : list) {
      SignAlgo signAlgo;
      try {
        signAlgo = SignAlgo.getInstance(n);
      } catch (NoSuchAlgorithmException ex) {
        throw new XiSecurityException(ex.getMessage(), ex);
      }
      pairs.putPair("algo", signAlgo.getJceName());
      signerConfs.add(new CaSignerConf(signAlgo, pairs.getEncoded()));
    }

    return signerConfs;
  } // method splitCaSignerConfs

  public NameId getIdent() {
    return ident;
  }

  public Validity getMaxValidity() {
    return maxValidity;
  }

  public void setMaxValidity(Validity maxValidity) {
    this.maxValidity = maxValidity;
  }

  public int getKeepExpiredCertInDays() {
    return keepExpiredCertInDays;
  }

  public void setKeepExpiredCertInDays(int days) {
    this.keepExpiredCertInDays = days;
  }

  public void setSignerConf(String signerConf) {
    this.signerConf = Args.notBlank(signerConf, "signerConf");
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

  public void setCrlControl(CrlControl crlControl) {
    this.crlControl = crlControl;
  }

  public CrlControl getCrlControl() {
    return crlControl;
  }

  public CtlogControl getCtlogControl() {
    return ctlogControl;
  }

  public void setCtlogControl(CtlogControl ctlogControl) {
    this.ctlogControl = ctlogControl;
  }

  public RevokeSuspendedControl getRevokeSuspendedControl() {
    return revokeSuspendedControl;
  }

  public void setRevokeSuspendedControl(RevokeSuspendedControl revokeSuspendedControl) {
    this.revokeSuspendedControl = revokeSuspendedControl;
  }

  public String getCrlSignerName() {
    return crlSignerName;
  }

  public void setCrlSignerName(String crlSignerName) {
    this.crlSignerName = (crlSignerName == null) ? null : crlSignerName.toLowerCase();
  }

  public List<String> getKeypairGenNames() {
    return keypairGenNames;
  }

  public void setKeypairGenNames(List<String> keypairGenNames) {
    this.keypairGenNames = (keypairGenNames == null) ? null : CollectionUtil.toLowerCaseList(keypairGenNames);
  }

  public boolean isSaveRequest() {
    return saveRequest;
  }

  public void setSaveRequest(boolean saveRequest) {
    this.saveRequest = saveRequest;
  }

  public boolean isSaveKeypair() {
    return saveKeypair;
  }

  public void setSaveKeypair(boolean saveKeypair) {
    this.saveKeypair = saveKeypair;
  }

  public boolean isSaveCert() {
    return saveCert;
  }

  public void setSaveCert(boolean saveCert) {
    this.saveCert = saveCert;
  }

  public ValidityMode getValidityMode() {
    return validityMode;
  }

  public void setValidityMode(ValidityMode mode) {
    this.validityMode = Args.notNull(mode, "mode");
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

    int certchainSize = certchain == null ? 0 : certchain.size();
    StringBuilder certchainStr = new StringBuilder(20 + certchainSize * 200);
    certchainStr.append("\ncertchain: ");
    if (certchainSize > 0) {
      for (int i = 0; i < certchainSize; i++) {
        certchainStr.append("\ncert[").append(i).append("]:\n");
        certchainStr.append(X509Util.formatCert(certchain.get(i), verbose));
      }
    } else {
      certchainStr.append("null");
    }

    List<String> permissionList = PermissionConstants.permissionToStringSet(permission);

    String permissionText = "";
    if (!permissionList.isEmpty()) {
      StringBuilder buffer = new StringBuilder();
      for (String m : permissionList) {
        buffer.append(m).append(", ");
      }
      permissionText = buffer.substring(0, buffer.length() - 2);
    }

    return StringUtil.concatObjectsCap(1500,
        "id: ", ident.getId(), "\nname: ", ident.getName(),
        "\nstatus: ", (status == null ? "null" : status.getStatus()),
        "\nmax. validity: ", maxValidity,
        "\nexpiration period: ", expirationPeriod, "d",
        "\nsigner type: ", signerType,
        "\nsigner conf: ", (signerConf == null ? "null"
            : SignerEntry.signerConfToString(signerConf, verbose, ignoreSensitiveInfo)),
        "\nCRL control:\n", (crlControl == null ? "  null" : crlControl.toString(verbose)),
        "\nCTLog control:\n", (ctlogControl == null ? "  null" : ctlogControl.toString()),
        "\nrevoke suspended certificates control: \n",
            (revokeSuspendedControl == null ? "  null" : revokeSuspendedControl.toString()),
        "\nCRL signer name: ", crlSignerName,
        "\nKeyPair generation names: ", keypairGenNames,
        "\nsave certificate: ", saveCert,
        "\nsave request: ", saveRequest,
        "\nsave keypair: ", saveKeypair,
        "\nvalidity mode: ", validityMode,
        "\npermission: ", permissionText,
        "\nkeep expired certs: ",
            (keepExpiredCertInDays < 0 ? "forever" : keepExpiredCertInDays + " days"),
        "\nextra control: ", extraCtrlText,
        "\nserial number length: ", serialNoLen, " bytes",
        "\nnext CRL number: ", nextCrlNumber, "\n", caUris,
        "\nrevocation: ", (revocationInfo == null ? "not revoked" : "revoked"), revInfoText,
        "\ncert: \n", X509Util.formatCert(cert, verbose),
        certchainStr.toString());
  } // method toString(boolean, boolean)

  protected static String urisToString(Collection<?> tokens) {
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
  } // method urisToString

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof CaEntry)) {
      return false;
    }

    return equals((CaEntry) obj, false, false);
  } // method equals(Object)

  public boolean equals(CaEntry obj, boolean ignoreDynamicFields, boolean ignoreId) {
    if (!ignoreDynamicFields) {
      if (nextCrlNumber != obj.nextCrlNumber) {
        return false;
      }
    }

    return CompareUtil.equalsObject(caUris, obj.caUris)
        && CompareUtil.equalsObject(cert, obj.cert)
        && CompareUtil.equalsObject(certchain, obj.certchain)
        && CompareUtil.equalsObject(crlControl, obj.crlControl)
        && CompareUtil.equalsObject(crlSignerName, obj.crlSignerName)
        && CompareUtil.equalsObject(ctlogControl, obj.ctlogControl)
        && (expirationPeriod == obj.expirationPeriod)
        && CompareUtil.equalsObject(extraControl, obj.extraControl)
        && ident.equals(obj.ident, ignoreId)
        && (keepExpiredCertInDays == obj.keepExpiredCertInDays)
        && CompareUtil.equalsObject(maxValidity, obj.maxValidity)
        // ignore dynamic field nextCrlNumber
        && (numCrls == obj.numCrls)
        && (permission == obj.permission)
        && CompareUtil.equalsObject(revocationInfo, obj.revocationInfo)
        && CompareUtil.equalsObject(revokeSuspendedControl, obj.revokeSuspendedControl)
        && (saveCert == obj.saveCert)
        && (saveRequest == obj.saveRequest)
        && (saveKeypair == obj.saveKeypair)
        && CompareUtil.equalsObject(keypairGenNames, obj.keypairGenNames)
        && (serialNoLen == obj.serialNoLen)
        && signerType.equals(obj.signerType)
        && CompareUtil.equalsObject(signerConf, obj.signerConf)
        && CompareUtil.equalsObject(status, obj.status)
        && CompareUtil.equalsObject(validityMode, obj.validityMode);
  } // method equals(Ca, boolean, boolean)

  @Override
  public int hashCode() {
    return ident.hashCode();
  }

  public void setCert(X509Cert cert)
      throws CaMgmtException {
    if (cert == null) {
      this.cert = null;
      this.subject = null;
      this.hexSha1OfCert = null;
    } else {
      if (!cert.hasKeyusage(KeyUsage.keyCertSign)) {
        throw new CaMgmtException("CA certificate does not have keyusage keyCertSign");
      }
      this.cert = cert;
      this.pathLenConstraint = cert.getBasicConstraints();
      if (this.pathLenConstraint < 0) {
        throw new CaMgmtException("given certificate is not a CA certificate");
      }
      this.subject = cert.getSubjectText();
      byte[] encodedCert = cert.getEncoded();
      this.hexSha1OfCert = HashAlgo.SHA1.hexHash(encodedCert);
    }
  } // method setCert

  public int getSerialNoLen() {
    return serialNoLen;
  }

  public void setSerialNoLen(int serialNoLen) {
    this.serialNoLen = Args.range(serialNoLen, "serialNoLen",
        CaManager.MIN_SERIALNUMBER_SIZE, CaManager.MAX_SERIALNUMBER_SIZE);
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

  public X509Cert getCert() {
    return cert;
  }

  public List<X509Cert> getCertchain() {
    return certchain;
  }

  public void setCertchain(List<X509Cert> certchain) {
    this.certchain = certchain;
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

  public String getSubject() {
    return subject;
  }

  public int getPathLenConstraint() {
    return pathLenConstraint;
  }

  public String getHexSha1OfCert() {
    return hexSha1OfCert;
  }

}
