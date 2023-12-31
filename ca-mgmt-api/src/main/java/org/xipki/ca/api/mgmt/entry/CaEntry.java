// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeyUsage;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.CompareUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;

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

  protected NameId ident;

  protected String signerConf;

  protected X509Cert cert;

  protected int pathLenConstraint;

  /**
   * certificate chain without the certificate specified in {@code #cert}. The first one issued
   * {@code #cert}, the second one issues the first one, and so on.
   */
  protected List<X509Cert> certchain;

  protected String subject;

  protected String hexSha1OfCert;

  // for deserializer
  private CaEntry() {
  }

  public CaEntry(NameId ident) {
    this.ident = Args.notNull(ident, "ident");
  }

  public CaEntry copy() {
    CaEntry ret = new CaEntry(ident);
    copyBaseInfoTo(ret);
    ret.pathLenConstraint = pathLenConstraint;
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
    int certchainSize = certchain == null ? 0 : certchain.size();
    StringBuilder certchainStr = new StringBuilder(20 + certchainSize * 200);
    certchainStr.append("\ncertchain: ");
    if (certchainSize > 0) {
      for (int i = 0; i < certchainSize; i++) {
        certchainStr.append("\ncert[").append(i).append("]:\n");
        certchainStr.append(X509Util.formatCert(certchain.get(i), verbose));
      }
    } else {
      certchainStr.append("-");
    }

    return StringUtil.concatObjectsCap(1500,
        "id:                   ", ident.getId(),
        "\nname:                 ", ident.getName(),
        "\nsigner conf:          ", (signerConf == null ? "-"
            : SignerEntry.signerConfToString(signerConf, verbose, ignoreSensitiveInfo)),
        super.toString(verbose),
        "\ncert: \n", X509Util.formatCert(cert, verbose),
        certchainStr.toString());
  }

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
        && ident.equals(obj.ident, ignoreId)
        && CompareUtil.equalsObject(signerConf, obj.signerConf);
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
