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

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeyUsage;
import org.xipki.security.SignerConf;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.CompareUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.Validity;

/**
 * CA management entry.
 *
 * @author Lijun Liao
 *
 */
public abstract class MgmtEntry {

  public static class AddUser extends MgmtEntry {

    private NameId ident;

    private boolean active;

    private String password;

    // For the deserialization only
    @SuppressWarnings("unused")
    private AddUser() {
    }

    public AddUser(NameId ident, boolean active, String password) throws CaMgmtException {
      this.ident = Args.notNull(ident, "ident");
      this.active = active;
      this.password = Args.notBlank(password, "password");
    }

    public void setIdent(NameId ident) {
      this.ident = ident;
    }

    public NameId getIdent() {
      return ident;
    }

    public void setActive(boolean active) {
      this.active = active;
    }

    public boolean isActive() {
      return active;
    }

    public void setPassword(String password) {
      this.password = password;
    }

    public String getPassword() {
      return password;
    }

    @Override
    public String toString() {
      return StringUtil.concatObjectsCap(200, "id: ", ident.getId(), "\nname: ", ident.getName(),
          "\nactive: ", active, "\npassword: ****\n");
    }

  } // class AddUser

  public static class Ca extends MgmtEntry {

    private NameId ident;

    private CaStatus status;

    private Validity maxValidity;

    private String signerType;

    private String signerConf;

    private String dhpocControl;

    private ScepControl scepControl;

    private CrlControl crlControl;

    private String crlSignerName;

    private CmpControl cmpControl;

    private CtlogControl ctlogControl;

    private RevokeSuspendedControl revokeSuspendedControl;

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

    /**
     * certificate chain without the certificate specified in {@code #cert}. The first one issued
     * {@code #cert}, the second one issues the first one, and so on.
     */
    private List<X509Certificate> certchain;

    private int serialNoBitLen;

    private long nextCrlNumber;

    private int numCrls;

    private CertRevocationInfo revocationInfo;

    private String subject;

    private String hexSha1OfCert;

    // For the deserialization only
    @SuppressWarnings("unused")
    private Ca() {
    }

    public Ca(NameId ident, int serialNoBitLen, long nextCrlNumber, String signerType,
        String signerConf, CaUris caUris, int numCrls, int expirationPeriod) {
      this.ident = Args.notNull(ident, "ident");
      this.signerType = Args.toNonBlankLower(signerType, "signerType");
      this.expirationPeriod = Args.notNegative(expirationPeriod, "expirationPeriod");
      this.signerConf = Args.notBlank(signerConf, "signerConf");

      this.numCrls = Args.positive(numCrls, "numCrls");
      this.serialNoBitLen = Args.range(serialNoBitLen, "serialNoBitLen",
          CaManager.MIN_SERIALNUMBER_SIZE, CaManager.MAX_SERIALNUMBER_SIZE);
      this.nextCrlNumber = Args.positive(nextCrlNumber, "nextCrlNumber");
      this.caUris = (caUris == null) ? CaUris.EMPTY_INSTANCE : caUris;
    } // constructor Ca

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

    public String getDhpocControl() {
      return dhpocControl;
    }

    public void setDhpocControl(String dhpocControl) {
      this.dhpocControl = dhpocControl;
    }

    public void setScepControl(ScepControl scepControl) {
      this.scepControl = scepControl;
    }

    public ScepControl getScepControl() {
      return scepControl;
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
      StringBuilder buffer = new StringBuilder();
      for (String m : permissionList) {
        buffer.append("\n  ").append(m);
      }
      String permissionText = buffer.toString();

      return StringUtil.concatObjectsCap(1500,
          "id: ", ident.getId(), "\nname: ", ident.getName(),
          "\nstatus: ", (status == null ? "null" : status.getStatus()),
          "\nmax. validity: ", maxValidity,
          "\nexpiration period: ", expirationPeriod, " days",
          "\nsigner type: ", signerType,
          "\nsigner conf: ", (signerConf == null
                ? "null" : signerConfToString(signerConf, verbose, ignoreSensitiveInfo)),
          "\nDHPoc control: ", (dhpocControl == null
                ? "null" : signerConfToString(dhpocControl, verbose, ignoreSensitiveInfo)),
          "\nCMP control:\n", (cmpControl == null ? "  null" : cmpControl.toString(verbose)),
          "\nCRL control:\n", (crlControl == null ? "  null" : crlControl.toString(verbose)),
          "\nSCEP control: \n", (scepControl == null ? "  null" : scepControl.toString(verbose)),
          "\nCTLog control: \n", (ctlogControl == null ? "  null" : ctlogControl.toString()),
          "\nrevoke suspended certificates control: \n",
              (revokeSuspendedControl == null ? "  null" : revokeSuspendedControl.toString()),
          "\nCMP responder name: ", cmpResponderName,
          "\nSCEP responder name: ", scepResponderName,
          "\nCRL signer name: ", crlSignerName,
          "\nduplicate key: ", duplicateKeyPermitted,
          "\nduplicate subject: ", duplicateSubjectPermitted,
          "\n", protocolSupport,
          "\nsave request: ", saveRequest,
          "\nvalidity mode: ", validityMode,
          "\npermission:", permissionText,
          "\nkeep expired certs: ",
              (keepExpiredCertInDays < 0 ? "forever" : keepExpiredCertInDays + " days"),
          "\nextra control: ", extraCtrlText,
          "\nserial number bit length: ", serialNoBitLen,
          "\nnext CRL number: ", nextCrlNumber, "\n", caUris,
          "\nrevocation: ", (revocationInfo == null ? "not revoked" : "revoked"), revInfoText,
          "\ncert: \n", X509Util.formatCert(cert, verbose),
          certchainStr.toString());
    } // method toString(boolean, boolean)

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
    } // method urisToString

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      } else if (!(obj instanceof Ca)) {
        return false;
      }

      return equals((Ca) obj, false, false);
    } // method equals(Object)

    public boolean equals(Ca obj, boolean ignoreDynamicFields, boolean ignoreId) {
      if (!ignoreDynamicFields) {
        if (nextCrlNumber != obj.nextCrlNumber) {
          return false;
        }
      }

      return CompareUtil.equalsObject(caUris, obj.caUris)
          && CompareUtil.equalsObject(cert, obj.cert)
          && CompareUtil.equalsObject(certchain, obj.certchain)
          && CompareUtil.equalsObject(cmpControl, obj.cmpControl)
          && CompareUtil.equalsObject(cmpResponderName, obj.cmpResponderName)
          && CompareUtil.equalsObject(crlControl, obj.crlControl)
          && CompareUtil.equalsObject(crlSignerName, obj.crlSignerName)
          && CompareUtil.equalsObject(ctlogControl, obj.ctlogControl)
          && CompareUtil.equalsObject(dhpocControl, obj.dhpocControl)
          && (duplicateKeyPermitted == obj.duplicateKeyPermitted)
          && (duplicateSubjectPermitted == obj.duplicateSubjectPermitted)
          && (expirationPeriod == obj.expirationPeriod)
          && CompareUtil.equalsObject(extraControl, obj.extraControl)
          && ident.equals(obj.ident, ignoreId)
          && (keepExpiredCertInDays == obj.keepExpiredCertInDays)
          && CompareUtil.equalsObject(maxValidity, obj.maxValidity)
          // ignore dynamic field nextCrlNumber
          && (numCrls == obj.numCrls)
          && (permission == obj.permission)
          && CompareUtil.equalsObject(protocolSupport, obj.protocolSupport)
          && CompareUtil.equalsObject(revocationInfo, obj.revocationInfo)
          && CompareUtil.equalsObject(revokeSuspendedControl, obj.revokeSuspendedControl)
          && (saveRequest == obj.saveRequest)
          && CompareUtil.equalsObject(scepControl, obj.scepControl)
          && CompareUtil.equalsObject(scepResponderName, obj.scepResponderName)
          && (serialNoBitLen == obj.serialNoBitLen)
          && signerType.equals(obj.signerType)
          && CompareUtil.equalsObject(signerConf, obj.signerConf)
          && CompareUtil.equalsObject(status, obj.status)
          && CompareUtil.equalsObject(validityMode, obj.validityMode);
    } // method equals(Ca, boolean, boolean)

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
    } // method setCert

    public int getSerialNoBitLen() {
      return serialNoBitLen;
    }

    public void setSerialNoBitLen(int serialNoBitLen) {
      this.serialNoBitLen = Args.range(serialNoBitLen, "serialNoBitLen",
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

    public X509Certificate getCert() {
      return cert;
    }

    public List<X509Certificate> getCertchain() {
      return certchain;
    }

    public void setCertchain(List<X509Certificate> certchain) {
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

    public String getHexSha1OfCert() {
      return hexSha1OfCert;
    }

  } // class Ca

  public static class CaHasRequestor extends MgmtEntry {

    private NameId requestorIdent;

    private boolean ra;

    private int permission;

    private Set<String> profiles;

    // For the deserialization only
    @SuppressWarnings("unused")
    private CaHasRequestor() {
    }

    public CaHasRequestor(NameId requestorIdent) {
      this.requestorIdent = Args.notNull(requestorIdent, "requestorIdent");
    }

    public boolean isRa() {
      return ra;
    }

    public void setRa(boolean ra) {
      this.ra = ra;
    }

    public int getPermission() {
      return permission;
    }

    public void setPermission(int permission) {
      this.permission = permission;
    }

    public NameId getRequestorIdent() {
      return requestorIdent;
    }

    public void setRequestorIdent(NameId requestorIdent) {
      this.requestorIdent = requestorIdent;
    }

    public void setProfiles(Set<String> profiles) {
      if (CollectionUtil.isEmpty(profiles)) {
        this.profiles = Collections.emptySet();
      } else {
        this.profiles = CollectionUtil.unmodifiableSet(CollectionUtil.toLowerCaseSet(profiles));
      }
    }

    public Set<String> getProfiles() {
      return profiles;
    }

    public boolean isCertprofilePermitted(String certprofile) {
      if (CollectionUtil.isEmpty(profiles)) {
        return false;
      }

      return profiles.contains("all") || profiles.contains(certprofile.toLowerCase());
    }

    public boolean isPermitted(int permission) {
      return PermissionConstants.contains(this.permission, permission);
    }

    @Override
    public String toString() {
      return StringUtil.concatObjectsCap(200, "requestor: ", requestorIdent,
          "\nra: ", ra, "\nprofiles: ", profiles,
          "\npermission: ", PermissionConstants.permissionToString(permission));
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      } else if (!(obj instanceof CaHasRequestor)) {
        return false;
      }

      return equals((CaHasRequestor) obj, false);
    }

    public boolean equals(CaHasRequestor obj, boolean ignoreId) {
      return (obj != null)
          && (ra == obj.ra)
          && requestorIdent.equals(obj.requestorIdent, ignoreId)
          && (permission == obj.permission)
          && CompareUtil.equalsObject(profiles, obj.profiles);
    }

    @Override
    public int hashCode() {
      return requestorIdent.hashCode();
    }

  } // class CaHasRequestor

  public static class CaHasUser extends MgmtEntry {

    private NameId userIdent;

    private int permission;

    private Set<String> profiles;

    // For the deserialization only
    @SuppressWarnings("unused")
    private CaHasUser() {
    }

    public CaHasUser(NameId userIdent) {
      this.userIdent = Args.notNull(userIdent, "userIdent");
    }

    public int getPermission() {
      return permission;
    }

    public void setPermission(int permission) {
      this.permission = permission;
    }

    public void setUserIdent(NameId userIdent) {
      this.userIdent = userIdent;
    }

    public NameId getUserIdent() {
      return userIdent;
    }

    public void setProfiles(Set<String> profiles) {
      this.profiles = CollectionUtil.unmodifiableSet(CollectionUtil.toLowerCaseSet(profiles));
    }

    public Set<String> getProfiles() {
      return profiles;
    }

    @Override
    public String toString() {
      return StringUtil.concatObjectsCap(200, "user: ", userIdent, "\nprofiles: ", profiles,
          "\npermission: ", PermissionConstants.permissionToString(permission));
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      } else if (!(obj instanceof CaHasUser)) {
        return false;
      }

      return equals((CaHasUser) obj, false);
    }

    public boolean equals(CaHasUser obj, boolean ignoreId) {
      return (obj != null)
          && userIdent.equals(obj.userIdent, ignoreId)
          && (permission == obj.permission)
          && CompareUtil.equalsObject(profiles, obj.profiles);
    }

    @Override
    public int hashCode() {
      return userIdent.hashCode();
    }

  } // method CaHasUser

  public static class Certprofile extends MgmtEntry {

    private NameId ident;

    private String type;

    private String conf;

    private boolean faulty;

    // For the deserialization only
    @SuppressWarnings("unused")
    private Certprofile() {
    }

    public Certprofile(NameId ident, String type, String conf) {
      this.ident = Args.notNull(ident, "ident");
      this.type = Args.toNonBlankLower(type, "type");
      this.conf = conf;
      if ("all".equalsIgnoreCase(ident.getName()) || "null".equalsIgnoreCase(ident.getName())) {
        throw new IllegalArgumentException("certificate profile name may not be 'all' and 'null'");
      }
    }

    public void setIdent(NameId ident) {
      if ("all".equalsIgnoreCase(ident.getName()) || "null".equalsIgnoreCase(ident.getName())) {
        throw new IllegalArgumentException("certificate profile name may not be 'all' and 'null'");
      }
      this.ident = Args.notNull(ident, "ident");
    }

    public void setType(String type) {
      this.type = Args.toNonBlankLower(type, "type");
    }

    public void setConf(String conf) {
      this.conf = conf;
    }

    public NameId getIdent() {
      return ident;
    }

    public String getType() {
      return type;
    }

    public String getConf() {
      return conf;
    }

    public boolean isFaulty() {
      return faulty;
    }

    public void setFaulty(boolean faulty) {
      this.faulty = faulty;
    }

    @Override
    public String toString() {
      return toString(false);
    }

    public String toString(boolean verbose) {
      boolean bo = (verbose || conf == null || conf.length() < 301);
      return StringUtil.concatObjectsCap(200, "id: ", ident.getId(), "\nname: ", ident.getName(),
          "\nfaulty: ", faulty, "\ntype: ", type, "\nconf: ",
          (bo ? conf : StringUtil.concat(conf.substring(0, 297), "...")));
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      } else if  (!(obj instanceof Certprofile)) {
        return false;
      }

      return equals((Certprofile) obj, false);
    }

    public boolean equals(Certprofile obj, boolean ignoreId) {
      if (!ident.equals(obj.ident, ignoreId)) {
        return false;
      }

      if (!type.equals(obj.type)) {
        return false;
      }

      if (!CompareUtil.equalsObject(conf, obj.conf)) {
        return false;
      }

      return true;
    }

    @Override
    public int hashCode() {
      return ident.hashCode();
    }

  } // class Certprofile

  public static class ChangeCa extends MgmtEntry {

    private NameId ident;

    private CaStatus status;

    private Validity maxValidity;

    private String signerType;

    private String signerConf;

    private String cmpControl;

    private String crlControl;

    private String scepControl;

    private String ctlogControl;

    private String dhpocControl;

    private String revokeSuspendedControl;

    private String cmpResponderName;

    private String scepResponderName;

    private String crlSignerName;

    private Boolean duplicateKeyPermitted;

    private Boolean duplicateSubjectPermitted;

    private Boolean supportCmp;

    private Boolean supportRest;

    private Boolean supportScep;

    private Boolean saveRequest;

    private ValidityMode validityMode;

    private Integer permission;

    private Integer keepExpiredCertInDays;

    private Integer expirationPeriod;

    private ConfPairs extraControl;

    private CaUris caUris;

    private byte[] encodedCert;

    private List<byte[]> encodedCertchain;

    private Integer numCrls;

    private Integer serialNoBitLen;

    // For the deserialization only
    @SuppressWarnings("unused")
    private ChangeCa() {
    }

    public ChangeCa(NameId ident) throws CaMgmtException {
      this.ident = Args.notNull(ident, "ident");
    }

    public void setIdent(NameId ident) {
      this.ident = Args.notNull(ident, "ident");
    }

    public NameId getIdent() {
      return ident;
    }

    public CaStatus getStatus() {
      return status;
    }

    public void setStatus(CaStatus status) {
      this.status = status;
    }

    public Validity getMaxValidity() {
      return maxValidity;
    }

    public void setMaxValidity(Validity maxValidity) {
      this.maxValidity = maxValidity;
    }

    public String getSignerType() {
      return signerType;
    }

    public void setSignerType(String signerType) {
      this.signerType = signerType == null ? null : signerType.toLowerCase();
    }

    public String getSignerConf() {
      return signerConf;
    }

    public void setSignerConf(String signerConf) {
      this.signerConf = signerConf;
    }

    public String getCmpControl() {
      return cmpControl;
    }

    public void setCmpControl(String cmpControl) {
      this.cmpControl = cmpControl;
    }

    public String getCrlControl() {
      return crlControl;
    }

    public void setCrlControl(String crlControl) {
      this.crlControl = crlControl;
    }

    public String getScepControl() {
      return scepControl;
    }

    public void setScepControl(String scepControl) {
      this.scepControl = scepControl;
    }

    public String getCtlogControl() {
      return ctlogControl;
    }

    public void setCtlogControl(String ctlogControl) {
      this.ctlogControl = ctlogControl;
    }

    public String getRevokeSuspendedControl() {
      return revokeSuspendedControl;
    }

    public void setRevokeSuspendedControl(String revokeSuspendedControl) {
      this.revokeSuspendedControl = revokeSuspendedControl;
    }

    public String getDhpocControl() {
      return dhpocControl;
    }

    public void setDhpocControl(String dhpocControl) {
      this.dhpocControl = dhpocControl;
    }

    public String getCmpResponderName() {
      return cmpResponderName;
    }

    public void setCmpResponderName(String responderName) {
      this.cmpResponderName = (responderName == null) ? null : responderName.toLowerCase();
    }

    public String getScepResponderName() {
      return scepResponderName;
    }

    public void setScepResponderName(String responderName) {
      this.scepResponderName = (responderName == null) ? null : responderName.toLowerCase();
    }

    public String getCrlSignerName() {
      return crlSignerName;
    }

    public void setCrlSignerName(String crlSignerName) {
      this.crlSignerName = (crlSignerName == null) ? null : crlSignerName.toLowerCase();
    }

    public Boolean getDuplicateKeyPermitted() {
      return duplicateKeyPermitted;
    }

    public void setDuplicateKeyPermitted(Boolean duplicateKeyPermitted) {
      this.duplicateKeyPermitted = duplicateKeyPermitted;
    }

    public Boolean getDuplicateSubjectPermitted() {
      return duplicateSubjectPermitted;
    }

    public void setDuplicateSubjectPermitted(Boolean duplicateSubjectPermitted) {
      this.duplicateSubjectPermitted = duplicateSubjectPermitted;
    }

    public ValidityMode getValidityMode() {
      return validityMode;
    }

    public void setValidityMode(ValidityMode validityMode) {
      this.validityMode = validityMode;
    }

    public Boolean getSupportCmp() {
      return supportCmp;
    }

    public void setSupportCmp(Boolean supportCmp) {
      this.supportCmp = supportCmp;
    }

    public Boolean getSupportRest() {
      return supportRest;
    }

    public void setSupportRest(Boolean supportRest) {
      this.supportRest = supportRest;
    }

    public Boolean getSupportScep() {
      return supportScep;
    }

    public void setSupportScep(Boolean supportScep) {
      this.supportScep = supportScep;
    }

    public Boolean getSaveRequest() {
      return saveRequest;
    }

    public void setSaveRequest(Boolean saveRequest) {
      this.saveRequest = saveRequest;
    }

    public Integer getPermission() {
      return permission;
    }

    public void setPermission(Integer permission) {
      this.permission = permission;
    }

    public Integer getExpirationPeriod() {
      return expirationPeriod;
    }

    public void setExpirationPeriod(Integer expirationPeriod) {
      this.expirationPeriod = expirationPeriod;
    }

    public Integer getKeepExpiredCertInDays() {
      return keepExpiredCertInDays;
    }

    public void setKeepExpiredCertInDays(Integer days) {
      this.keepExpiredCertInDays = days;
    }

    public ConfPairs getExtraControl() {
      return extraControl;
    }

    public void setExtraControl(ConfPairs extraControl) {
      this.extraControl = extraControl;
    }

    public Integer getSerialNoBitLen() {
      return serialNoBitLen;
    }

    public void setSerialNoBitLen(Integer serialNoBitLen) {
      if (serialNoBitLen != null) {
        Args.range(serialNoBitLen, "serialNoBitLen",
            CaManager.MIN_SERIALNUMBER_SIZE, CaManager.MAX_SERIALNUMBER_SIZE);
      }
      this.serialNoBitLen = serialNoBitLen;
    }

    public CaUris getCaUris() {
      return caUris;
    }

    public void setCaUris(CaUris caUris) {
      this.caUris = caUris;
    }

    public byte[] getEncodedCert() {
      return encodedCert;
    }

    public void setEncodedCert(byte[] encodedCert) {
      this.encodedCert = encodedCert;
    }

    public List<byte[]> getEncodedCertchain() {
      return encodedCertchain;
    }

    public void setEncodedCertchain(List<byte[]> encodedCertchain) {
      this.encodedCertchain = encodedCertchain;
    }

    public Integer getNumCrls() {
      return numCrls;
    }

    public void setNumCrls(Integer numCrls) {
      this.numCrls = numCrls;
    }

  } // class ChangeCa

  public static class ChangeUser extends MgmtEntry {

    private NameId ident;

    private Boolean active;

    private String password;

    // For the deserialization only
    @SuppressWarnings("unused")
    private ChangeUser() {
    }

    public ChangeUser(NameId ident) throws CaMgmtException {
      this.ident = Args.notNull(ident, "ident");
    }

    public void setIdent(NameId ident) {
      this.ident = Args.notNull(ident, "ident");
    }

    public NameId getIdent() {
      return ident;
    }

    public Boolean getActive() {
      return active;
    }

    public void setActive(Boolean active) {
      this.active = active;
    }

    public String getPassword() {
      return password;
    }

    public void setPassword(String password) {
      this.password = password;
    }

  } // class ChangeUser

  public static class Publisher extends MgmtEntry {

    private NameId ident;

    private String type;

    private String conf;

    private boolean faulty;

    // For the deserialization only
    @SuppressWarnings("unused")
    private Publisher() {
    }

    public Publisher(NameId ident, String type, String conf) {
      this.ident = Args.notNull(ident, "ident");
      this.type = Args.toNonBlankLower(type, "type");
      this.conf = conf;
    }

    public void setIdent(NameId ident) {
      this.ident = Args.notNull(ident, "ident");
    }

    public NameId getIdent() {
      return ident;
    }

    public void setType(String type) {
      this.type = Args.toNonBlankLower(type, "type");
    }

    public String getType() {
      return type;
    }

    public void setConf(String conf) {
      this.conf = conf;
    }

    public String getConf() {
      return conf;
    }

    public boolean isFaulty() {
      return faulty;
    }

    public void setFaulty(boolean faulty) {
      this.faulty = faulty;
    }

    @Override
    public String toString() {
      return StringUtil.concatObjectsCap(200, "id: ", ident.getId(), "\nname: ", ident.getName(),
          "\nfaulty: ", faulty, "\ntype: ", type, "\nconf: ", conf);
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      } else if (!(obj instanceof Publisher)) {
        return false;
      }

      return equals((Publisher) obj, false);
    }

    public boolean equals(Publisher obj, boolean ignoreId) {
      return (obj != null)
          && ident.equals(obj.ident, ignoreId)
          && type.equals(obj.type)
          && CompareUtil.equalsObject(conf, obj.conf);
    }

    @Override
    public int hashCode() {
      return ident.hashCode();
    }

  } // class Publisher

  public static class Requestor extends MgmtEntry {

    /**
     * Certificate.
     */
    public static final String TYPE_CERT = "cert";

    /**
     * Password based MAC.
     */
    public static final String TYPE_PBM = "pbm";

    private NameId ident;

    private String type;

    private String conf;

    private boolean faulty;

    // For the deserialization only
    @SuppressWarnings("unused")
    private Requestor() {
    }

    public Requestor(NameId ident, String type, String conf) {
      this.ident = Args.notNull(ident, "ident");
      String name = ident.getName();
      if (RequestorInfo.NAME_BY_USER.equalsIgnoreCase(name)
          || RequestorInfo.NAME_BY_CA.equalsIgnoreCase(name)) {
        throw new IllegalArgumentException("Requestor name could not be " + name);
      }

      this.type = Args.notBlank(type, "type");
      this.conf = Args.notBlank(conf, "conf");
    }

    public void setIdent(NameId ident) {
      this.ident = Args.notNull(ident, "ident");
      String name = ident.getName();
      if (RequestorInfo.NAME_BY_USER.equalsIgnoreCase(name)
          || RequestorInfo.NAME_BY_CA.equalsIgnoreCase(name)) {
        throw new IllegalArgumentException("Requestor name could not be " + name);
      }
    }

    public void setType(String type) {
      this.type = Args.notBlank(type, "type");
    }

    public void setConf(String conf) {
      this.conf = Args.notBlank(conf, "conf");
    }

    public NameId getIdent() {
      return ident;
    }

    public String getType() {
      return type;
    }

    public String getConf() {
      return conf;
    }

    public void setFaulty(boolean faulty) {
      this.faulty = faulty;
    }

    public boolean isFaulty() {
      return faulty;
    }

    @Override
    public String toString() {
      return toString(false);
    }

    public String toString(boolean verbose) {
      StringBuilder sb = new StringBuilder(500);
      sb.append("id: ").append(ident.getId());
      sb.append("\nname: ").append(ident.getName());
      sb.append("\ntype: ").append(type);

      sb.append("\nconf: ");
      if (verbose || conf.length() < 101) {
        sb.append(conf);
      } else {
        sb.append(conf.substring(0, 97)).append("...");
      }

      sb.append("\nfaulty: ").append(faulty).append('\n');

      if (!faulty && TYPE_CERT.equalsIgnoreCase(type)) {
        try {
          X509Certificate cert = X509Util.parseCert(StringUtil.toUtf8Bytes(conf));
          sb.append("cert:");
          sb.append("\n\tissuer: ").append(X509Util.getRfc4519Name(cert.getIssuerX500Principal()));
          sb.append("\n\tserialNumber: ").append(LogUtil.formatCsn(cert.getSerialNumber()));
          sb.append("\n\tsubject: ")
            .append(X509Util.getRfc4519Name(cert.getSubjectX500Principal())).append('\n');
        } catch (CertificateException ex) {
          sb.append("cert: ERROR(").append(ex.getMessage()).append(")\n");
        }
      }

      return sb.toString();
    } // method toString(boolean)

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      } else if (!(obj instanceof Requestor)) {
        return false;
      }

      return equals((Requestor) obj, false);
    }

    public boolean equals(Requestor obj, boolean ignoreId) {
      return (obj != null)
          && ident.equals(obj.ident, ignoreId)
          && type.equals(obj.type)
          && conf.equals(obj.conf);
    }

    @Override
    public int hashCode() {
      return ident.hashCode();
    }

  } // class Requestor

  public static class Signer extends MgmtEntry {

    private final String name;

    private final String type;

    private String conf;

    private boolean certFaulty;

    private boolean confFaulty;

    private final String base64Cert;

    private X509Certificate certificate;

    public Signer(String name, String type, String conf, String base64Cert) {
      this.name = Args.toNonBlankLower(name, "name");
      this.type = Args.toNonBlankLower(type, "type");
      this.conf = conf;
      this.base64Cert = base64Cert;

      if (base64Cert == null) {
        return;
      }

      try {
        this.certificate = X509Util.parseCert(StringUtil.toUtf8Bytes(base64Cert));
      } catch (Throwable th) {
        this.certFaulty = true;
      }
    }

    public String getName() {
      return name;
    }

    public String getType() {
      return type;
    }

    public void setConf(String conf) {
      this.conf = conf;
    }

    public String getConf() {
      return conf;
    }

    public X509Certificate getCertificate() {
      return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
      if (base64Cert != null) {
        throw new IllegalStateException("certificate is already specified by base64Cert");
      }
      this.certificate = certificate;
    }

    public String getBase64Cert() {
      return base64Cert;
    }

    public boolean isFaulty() {
      return confFaulty || certFaulty;
    }

    public void setConfFaulty(boolean confFaulty) {
      this.confFaulty = confFaulty;
    }

    @Override
    public String toString() {
      return toString(false);
    }

    public String toString(boolean verbose) {
      return toString(verbose, true);
    }

    public String toString(boolean verbose, boolean ignoreSensitiveInfo) {
      StringBuilder sb = new StringBuilder(1000);
      sb.append("name: ").append(name).append('\n');
      sb.append("faulty: ").append(isFaulty()).append('\n');
      sb.append("type: ").append(type).append('\n');
      sb.append("conf: ");
      if (conf == null) {
        sb.append("null");
      } else {
        sb.append(signerConfToString(conf, verbose, ignoreSensitiveInfo));
      }
      sb.append('\n');
      sb.append("certificate: ").append("\n");
      if (certificate != null || base64Cert != null) {
        if (certificate != null) {
          sb.append("\tissuer: ").append(X509Util.getRfc4519Name(
              certificate.getIssuerX500Principal())).append('\n');
          sb.append("\tserialNumber: ")
              .append(LogUtil.formatCsn(certificate.getSerialNumber())).append('\n');
          sb.append("\tsubject: ").append(X509Util.getRfc4519Name(
              certificate.getSubjectX500Principal()));
        }
        if (verbose) {
          sb.append("\n\tencoded: ");
          try {
            sb.append(Base64.encodeToString(certificate.getEncoded()));
          } catch (CertificateEncodingException ex) {
            sb.append("ERROR");
          }
        }
      } else {
        sb.append("  null");
      }
      return sb.toString();
    } // method toString(boolean, boolean)

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      } else if (!(obj instanceof Signer)) {
        return false;
      }

      Signer objB = (Signer) obj;
      return name.equals(objB.name)
          && type.equals(objB.type)
          && CompareUtil.equalsObject(conf, objB.conf)
          && CompareUtil.equalsObject(base64Cert, objB.base64Cert);
    } // method equals

    @Override
    public int hashCode() {
      return name.hashCode();
    }

  } // class Signer

  public static class User extends MgmtEntry {

    private NameId ident;

    private boolean active;

    private String hashedPassword;

    // For the deserialization only
    @SuppressWarnings("unused")
    private User() {
    }

    public User(NameId ident, boolean active, String hashedPassword) throws CaMgmtException {
      this.ident = Args.notNull(ident, "ident");
      this.active = active;
      this.hashedPassword = Args.notBlank(hashedPassword, "hashedPassword");
    }

    public void setIdent(NameId ident) {
      this.ident = Args.notNull(ident, "ident");
    }

    public NameId getIdent() {
      return ident;
    }

    public void setActive(boolean active) {
      this.active = active;
    }

    public boolean isActive() {
      return active;
    }

    public void setHashedPassword(String hashedPassword) {
      this.hashedPassword = Args.notBlank(hashedPassword, "hashedPassword");
    }

    public String getHashedPassword() {
      return hashedPassword;
    }

    @Override
    public int hashCode() {
      return ident.hashCode() + 31 + hashedPassword.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      } else if  (!(obj instanceof User)) {
        return false;
      }

      return equals((User) obj, false);
    }

    public boolean equals(User obj, boolean ignoreId) {
      if (!ident.equals(obj.ident, ignoreId)) {
        return false;
      }

      return hashedPassword.equals(obj.hashedPassword);
    }

    @Override
    public String toString() {
      return StringUtil.concatObjectsCap(200, "id: ", ident.getId(), "\nname: ", ident.getName(),
          "\nactive: ", active, "\npassword: *****\n");
    }

  } // class User

  private static String signerConfToString(String signerConf, boolean verbose,
      boolean ignoreSensitiveInfo) {
    Args.notBlank(signerConf, "signerConf");
    if (ignoreSensitiveInfo) {
      signerConf = SignerConf.eraseSensitiveData(signerConf);
    }

    if (verbose || signerConf.length() < 101) {
      return signerConf;
    } else {
      return StringUtil.concat(signerConf.substring(0, 97), "...");
    }
  } // method signerConfToString

}
