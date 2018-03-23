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

package org.xipki.ca.server.mgmt.api.x509;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeyUsage;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CaEntry extends CaEntry {

  private List<String> crlUris;

  private List<String> deltaCrlUris;

  private List<String> ocspUris;

  private List<String> cacertUris;

  private X509Certificate cert;

  private String crlSignerName;

  private int serialNoBitLen;

  private long nextCrlNumber;

  private int numCrls;

  private CertRevocationInfo revocationInfo;

  private String subject;

  private String hexSha1OfCert;

  public X509CaEntry(NameId nameId, int serialNoBitLen, long nextCrlNumber, String signerType,
      String signerConf, X509CaUris caUris, int numCrls, int expirationPeriod)
      throws CaMgmtException {
    super(nameId, signerType, signerConf, expirationPeriod);
    init(serialNoBitLen, nextCrlNumber, caUris, numCrls);
  }

  private void init(int serialNoBitLen, long nextCrlNumber, X509CaUris caUris, int numCrls)
      throws CaMgmtException {
    this.numCrls = ParamUtil.requireMin("numCrls", numCrls, 1);
    this.serialNoBitLen = ParamUtil.requireRange("serialNoBitLen", serialNoBitLen, 63, 159);
    this.nextCrlNumber = ParamUtil.requireMin("nextCrlNumber", nextCrlNumber, 1);

    this.cacertUris = caUris.getCacertUris();
    this.ocspUris = caUris.getOcspUris();
    this.crlUris = caUris.getCrlUris();
    this.deltaCrlUris = caUris.getDeltaCrlUris();
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

  public int getserialNoBitLen() {
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

  public List<String> getCacertUris() {
    return cacertUris;
  }

  public String getCacertUrisAsString() {
    return urisToString(cacertUris);
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

  public String toString(boolean verbose, boolean ignoreSensitiveInfo) {
    String superToStr = super.toString(verbose, ignoreSensitiveInfo);
    String str = StringUtil.concatObjectsCap(1000, superToStr,
        (superToStr.charAt(superToStr.length() - 1) == '\n' ? "" : "\n"),
        "serialNoBitLen: ", serialNoBitLen, "\nnextCrlNumber: ", nextCrlNumber,
        "\ndeltaCrlUris:", formatUris(deltaCrlUris), "\ncrlUris:", formatUris(crlUris),
        "\nocspUris:", formatUris(ocspUris), "\ncaCertUris:", formatUris(cacertUris),
        "\ncert: \n", InternUtil.formatCert(cert, verbose),
        "\ncrlSignerName: ", crlSignerName,
        "\nrevocation: ", (revocationInfo == null ? "not revoked" : "revoked"), "\n");

    if (revocationInfo == null) {
      return str;
    }

    return StringUtil.concatObjectsCap(str.length() + 30,  str,
        "\treason: ", revocationInfo.getReason().getDescription(),
        "\n\trevoked at ", revocationInfo.getRevocationTime(), "\n");
  } // method toString

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

  @Override
  public void setExtraControl(ConfPairs extraControl) {
    super.setExtraControl(extraControl);
  }

  @Override
  public boolean equals(Object obj) {
    return equals(obj, false);
  }

  public boolean equals(Object obj, boolean ignoreDynamicFields) {
    if (! (obj instanceof X509CaEntry)) {
      return false;
    }

    if (!super.equals(obj)) {
      return false;
    }

    X509CaEntry objB = (X509CaEntry) obj;

    if (!ignoreDynamicFields) {
      if (nextCrlNumber != objB.nextCrlNumber) {
        return false;
      }
    }

    if (!CompareUtil.equalsObject(crlUris, objB.crlUris)) {
      return false;
    }

    if (!CompareUtil.equalsObject(deltaCrlUris, objB.deltaCrlUris)) {
      return false;
    }

    if (!CompareUtil.equalsObject(ocspUris, objB.ocspUris)) {
      return false;
    }

    if (!CompareUtil.equalsObject(cacertUris, objB.cacertUris)) {
      return false;
    }

    if (!CompareUtil.equalsObject(cert, objB.cert)) {
      return false;
    }

    if (!CompareUtil.equalsObject(crlSignerName, objB.crlSignerName)) {
      return false;
    }

    if (serialNoBitLen != objB.serialNoBitLen) {
      return false;
    }

    if (numCrls != objB.numCrls) {
      return false;
    }

    if (!CompareUtil.equalsObject(revocationInfo, objB.revocationInfo)) {
      return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    return getIdent().hashCode();
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
