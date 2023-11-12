// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.CtlogControl;
import org.xipki.ca.api.mgmt.RevokeSuspendedControl;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Management Entry CA.
 * @author Lijun Liao (xipki)
 *
 */

public class CaEntry extends BaseCaInfo {

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

  private String signerConf;

  private CrlControl crlControl;

  private CtlogControl ctlogControl;

  private RevokeSuspendedControl revokeSuspendedControl;

  private int permission;

  private ConfPairs extraControl;

  private X509Cert cert;

  private int pathLenConstraint;

  /**
   * certificate chain without the certificate specified in {@code #cert}. The first one issued
   * {@code #cert}, the second one issues the first one, and so on.
   */
  private List<X509Cert> certchain;

  private String subject;

  private String hexSha1OfCert;

  // for deserializer
  private CaEntry() {
  }

  public CaEntry(NameId ident, int serialNoLen, long nextCrlNo, String signerType,
      String signerConf, CaUris caUris, int numCrls, int expirationPeriod) {
    this.ident = Args.notNull(ident, "ident");
    this.signerType = Args.toNonBlankLower(signerType, "signerType");
    this.expirationPeriod = Args.notNegative(expirationPeriod, "expirationPeriod");
    this.signerConf = Args.notBlank(signerConf, "signerConf");

    setNumCrls(numCrls);
    setSnSize(serialNoLen);
    this.caUris = (caUris == null) ? CaUris.EMPTY_INSTANCE : caUris;
    setNextCrlNo(nextCrlNo);
  } // constructor Ca

  public CaEntry copy() {
    CaEntry ret = new CaEntry(ident, snSize, nextCrlNo, signerType, signerConf, caUris, numCrls, expirationPeriod);
    ret.nextCrlNo = nextCrlNo;
    ret.status = status;
    ret.maxValidity = maxValidity;
    ret.crlControl = crlControl;
    ret.crlSignerName = crlSignerName;
    ret.ctlogControl = ctlogControl;
    ret.revokeSuspendedControl = revokeSuspendedControl;
    ret.keypairGenNames = keypairGenNames;
    ret.saveKeypair = saveKeypair;
    ret.saveCert = saveCert;
    ret.validityMode = validityMode;
    ret.permission = permission;
    ret.keepExpiredCertDays = keepExpiredCertDays;
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

  public void setSignerConf(String signerConf) {
    this.signerConf = Args.notBlank(signerConf, "signerConf");
  }

  public String getSignerConf() {
    return signerConf;
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

  public int getPermission() {
    return permission;
  }

  public void setPermission(int permission) {
    this.permission = permission;
  }

  public ConfPairs getExtraControl() {
    return extraControl;
  }

  public void setExtraControl(ConfPairs extraControl) {
    this.extraControl = extraControl;
  }

  public void setIdent(NameId ident) {
    this.ident = ident;
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
        "id:                   ", ident.getId(),
        "\nname:                 ", ident.getName(),
        "\nstatus:               ", (status == null ? "null" : status.getStatus()),
        "\nmax. validity:        ", maxValidity,
        "\nexpiration period:    ", expirationPeriod, "d",
        "\nsigner type:          ", signerType,
        "\nsigner conf:          ", (signerConf == null ? "null"
            : SignerEntry.signerConfToString(signerConf, verbose, ignoreSensitiveInfo)),
        "\nCRL signer name:      ", crlSignerName,
        "\nsave certificate:     ", saveCert,
        "\nsave keypair:         ", saveKeypair,
        "\nvalidity mode:        ", validityMode,
        "\npermission:           ", permissionText,
        "\nkeep expired certs:   ", (keepExpiredCertDays < 0 ? "forever" : keepExpiredCertDays + " days"),
        "\nextra control:        ", extraCtrlText,
        "\nserial number length: ", snSize, " bytes",
        "\nrevocation:           ", (revocationInfo == null ? "not revoked" : "revoked"), revInfoText,
        "\nnext CRL number:      ", nextCrlNo,
        "\nKeyPair generation names: ", keypairGenNames,
        "\n", caUris,
        "\nCRL control:\n", (crlControl == null ? "  null" : crlControl.toString(verbose)),
        "\nCTLog control:\n", (ctlogControl == null ? "  null" : ctlogControl.toString()),
        "\nrevoke suspended certificates control: \n",
        (revokeSuspendedControl == null ? "  null" : revokeSuspendedControl.toString()),
        "\ncert: \n", X509Util.formatCert(cert, verbose),
        certchainStr.toString());
  } // method toString(boolean, boolean)

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
    return super.equals(obj, ignoreDynamicFields)
        && CompareUtil.equalsObject(cert, obj.cert)
        && CompareUtil.equalsObject(certchain, obj.certchain)
        && CompareUtil.equalsObject(crlControl, obj.crlControl)
        && CompareUtil.equalsObject(ctlogControl, obj.ctlogControl)
        && (expirationPeriod == obj.expirationPeriod)
        && CompareUtil.equalsObject(extraControl, obj.extraControl)
        && ident.equals(obj.ident, ignoreId)
        && (keepExpiredCertDays == obj.keepExpiredCertDays)
        && (numCrls == obj.numCrls)
        && (permission == obj.permission)
        && CompareUtil.equalsObject(revokeSuspendedControl, obj.revokeSuspendedControl)
        && CompareUtil.equalsObject(signerConf, obj.signerConf)
        && CompareUtil.equalsObject(validityMode, obj.validityMode);
  }

  @Override
  public int hashCode() {
    return ident.hashCode();
  }

  public void setCert(X509Cert cert) throws CaMgmtException {
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

  public X509Cert getCert() {
    return cert;
  }

  public List<X509Cert> getCertchain() {
    return certchain;
  }

  public void setCertchain(List<X509Cert> certchain) {
    this.certchain = certchain;
  }

  public int pathLenConstraint() {
    return pathLenConstraint;
  }

  public String subject() {
    return subject;
  }

  public String hexSha1OfCert() {
    return hexSha1OfCert;
  }
}
