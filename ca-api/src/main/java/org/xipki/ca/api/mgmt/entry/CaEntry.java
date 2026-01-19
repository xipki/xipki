// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeyUsage;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.CompareUtil;
import org.xipki.util.misc.StringUtil;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

/**
 * Management Entry CA.
 * @author Lijun Liao (xipki)
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

  private final NameId ident;

  private final BaseCaInfo base;

  private String signerConf;

  private X509Cert cert;

  private int pathLenConstraint;

  /**
   * certificate chain without the certificate specified in {@code #cert}. The
   * first one issued {@code #cert}, the second one issues the first one, and
   * so on.
   */
  private List<X509Cert> certchain;

  private String subject;

  private String hexSha1OfCert;

  public CaEntry(BaseCaInfo base, NameId ident, String signerConf) {
    this.base = Args.notNull(base, "base");
    this.ident = Args.notNull(ident, "ident");

    if (signerConf != null) {
      Args.notBlank(signerConf, "signerConf");
    }
    this.signerConf = signerConf;
  }

  public BaseCaInfo getBase() {
    return base;
  }

  public CaEntry copy() {
    CaEntry ret = new CaEntry(base, ident, signerConf);
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

  public String getSignerConf() {
    return signerConf;
  }

  public void setSignerConf(String signerConf) {
    this.signerConf = signerConf;
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
            : SignerEntry.signerConfToString(signerConf, verbose,
                ignoreSensitiveInfo)),
        base.toString(verbose),
        "\ncert: \n", X509Util.formatCert(cert, verbose),
        "\ncertchain: ", certchainStr.toString());
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

  public boolean equals(CaEntry obj, boolean ignoreDynamicFields,
                        boolean ignoreId) {
    return base.equals(obj.base, ignoreDynamicFields)
        && CompareUtil.equals(cert, obj.cert)
        && CompareUtil.equals(certchain, obj.certchain)
        && CompareUtil.equals(ident, obj.ident)
        && CompareUtil.equals(signerConf, obj.signerConf);
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
        throw new CaMgmtException(
            "CA certificate does not have keyusage keyCertSign");
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

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();
    ret.put("id", ident.getId());
    ret.put("name", ident.getName());

    base.toJson(ret);

    if (cert != null) {
      ret.put("cert", cert.getEncoded());
    }

    if (certchain != null) {
      JsonList list = new JsonList();
      for (X509Cert v : certchain) {
        list.add(v.getEncoded());
      }
      ret.put("certchain", list);
    }

    return ret.put("signerConf", signerConf)
        .put("pathLenConstraint", pathLenConstraint);
  }

  public static CaEntry parse(JsonMap json) throws CodecException {
    BaseCaInfo base = BaseCaInfo.parse(json);
    String signerConf = json.getNnString("signerConf");

    CaEntry ret = new CaEntry(base,
        new NameId(json.getInt("id"), json.getNnString("name")),
        signerConf);

    try {
      byte[] bytes = json.getBytes("cert");
      if (bytes != null) {
        ret.setCert(X509Util.parseCert(bytes));
      }

      List<byte[]> list = json.getBytesList("certchain");
      if (list != null) {
        List<X509Cert> certchain = new ArrayList<>(list.size());
        ret.setCertchain(certchain);

        for (byte[] v : list) {
          certchain.add(X509Util.parseCert(v));
        }
      }
    } catch (CaMgmtException | CertificateException e) {
      throw new CodecException(
          "could not decode certificate: " + e.getMessage(), e);
    }

    Integer i = json.getInt("pathLenConstraint");
    if (i != null) {
      ret.pathLenConstraint = i;
    }

    return ret;
  }

}
