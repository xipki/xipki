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

package org.xipki.ca.api;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PublicCaInfo {

  private final X500Principal subject;

  private final X500Name x500Subject;

  private final String c14nSubject;

  private final byte[] subjectKeyIdentifier;

  private final GeneralNames subjectAltName;

  private final BigInteger serialNumber;

  private final X509Cert caCert;

  private X509Certificate crlSignerCert;

  private final List<String> caCertUris;

  private final List<String> ocspUris;

  private final List<String> crlUris;

  private final List<String> deltaCrlUris;

  private final ConfPairs extraControl;

  public PublicCaInfo(X509Certificate caCert, List<String> caCertUris, List<String> ocspUris,
      List<String> crlUris, List<String> deltaCrlUris, ConfPairs extraControl)
      throws OperationException {
    ParamUtil.requireNonNull("caCert", caCert);

    this.caCert = new X509Cert(caCert);
    this.serialNumber = caCert.getSerialNumber();
    this.subject = caCert.getSubjectX500Principal();
    this.x500Subject = X500Name.getInstance(subject.getEncoded());
    this.c14nSubject = X509Util.canonicalizName(x500Subject);
    try {
      this.subjectKeyIdentifier = X509Util.extractSki(caCert);
    } catch (CertificateEncodingException ex) {
      throw new OperationException(ErrorCode.INVALID_EXTENSION, ex);
    }
    this.caCertUris = CollectionUtil.unmodifiableList(caCertUris);
    this.ocspUris = CollectionUtil.unmodifiableList(ocspUris);
    this.crlUris = CollectionUtil.unmodifiableList(crlUris);
    this.deltaCrlUris = CollectionUtil.unmodifiableList(deltaCrlUris);
    this.extraControl = extraControl;

    byte[] encodedSubjectAltName = caCert.getExtensionValue(
        Extension.subjectAlternativeName.getId());
    if (encodedSubjectAltName == null) {
      subjectAltName = null;
    } else {
      try {
        subjectAltName = GeneralNames.getInstance(
            X509ExtensionUtil.fromExtensionValue(encodedSubjectAltName));
      } catch (IOException ex) {
        throw new OperationException(ErrorCode.INVALID_EXTENSION,
            "invalid SubjectAltName extension in CA certificate");
      }
    }
  } // constructor

  public PublicCaInfo(X500Name subject, BigInteger serialNumber, GeneralNames subjectAltName,
      byte[] subjectKeyIdentifier, List<String> caCertUris, List<String> ocspUris,
      List<String> crlUris, List<String> deltaCrlUris, ConfPairs extraControl)
      throws OperationException {
    this.x500Subject = ParamUtil.requireNonNull("subject", subject);
    this.serialNumber = ParamUtil.requireNonNull("serialNumber", serialNumber);

    this.caCert = null;
    this.c14nSubject = X509Util.canonicalizName(subject);
    try {
      this.subject = new X500Principal(subject.getEncoded());
    } catch (IOException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE,
          "invalid SubjectAltName extension in CA certificate");
    }

    this.subjectKeyIdentifier = (subjectKeyIdentifier == null) ? null
        : Arrays.copyOf(subjectKeyIdentifier, subjectKeyIdentifier.length);

    this.subjectAltName = subjectAltName;
    this.caCertUris = CollectionUtil.unmodifiableList(caCertUris);
    this.ocspUris = CollectionUtil.unmodifiableList(ocspUris);
    this.crlUris = CollectionUtil.unmodifiableList(crlUris);
    this.deltaCrlUris = CollectionUtil.unmodifiableList(deltaCrlUris);
    this.extraControl = extraControl;
  } // constructor

  public List<String> getCaCertUris() {
    return caCertUris;
  }

  public List<String> getOcspUris() {
    return ocspUris;
  }

  public List<String> getCrlUris() {
    return crlUris;
  }

  public List<String> getDeltaCrlUris() {
    return deltaCrlUris;
  }

  public X509Certificate getCrlSignerCert() {
    return crlSignerCert;
  }

  public void setCrlSignerCert(X509Certificate crlSignerCert) {
    this.crlSignerCert = caCert.getCert().equals(crlSignerCert) ? null : crlSignerCert;
  }

  public X500Principal getSubject() {
    return subject;
  }

  public X500Name getX500Subject() {
    return x500Subject;
  }

  public String getC14nSubject() {
    return c14nSubject;
  }

  public GeneralNames getSubjectAltName() {
    return subjectAltName;
  }

  public byte[] getSubjectKeyIdentifer() {
    if (caCert != null) {
      return caCert.getSubjectKeyIdentifier();
    } else {
      return (subjectKeyIdentifier == null) ? null
          : Arrays.copyOf(subjectKeyIdentifier, subjectKeyIdentifier.length);
    }
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public X509Cert getCaCert() {
    return caCert;
  }

  public ConfPairs getExtraControl() {
    return extraControl;
  }

}
