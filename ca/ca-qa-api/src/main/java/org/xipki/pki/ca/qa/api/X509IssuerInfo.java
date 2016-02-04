/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.qa.api;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.Arrays;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509IssuerInfo {

  private final Set<String> caIssuerURLs;

  private final Set<String> ocspURLs;

  private final Set<String> crlURLs;

  private final Set<String> deltaCrlURLs;

  private final X509Certificate cert;

  private final Certificate bcCert;

  private final byte[] ski;

  public X509IssuerInfo(
      final List<String> caIssuerURLs,
      final List<String> ocspURLs,
      final List<String> crlURLs,
      final List<String> deltaCrlURLs,
      final byte[] certBytes)
  throws CertificateException {
    ParamUtil.assertNotNull("certBytes", certBytes);

    if (CollectionUtil.isEmpty(caIssuerURLs)) {
      this.caIssuerURLs = null;
    } else {
      Set<String> set = new HashSet<>();
      set.addAll(caIssuerURLs);
      this.caIssuerURLs = Collections.unmodifiableSet(set);
    }

    if (CollectionUtil.isEmpty(ocspURLs)) {
      this.ocspURLs = null;
    } else {
      Set<String> set = new HashSet<>();
      set.addAll(ocspURLs);
      this.ocspURLs = Collections.unmodifiableSet(set);
    }

    if (CollectionUtil.isEmpty(crlURLs)) {
      this.crlURLs = null;
    } else {
      Set<String> set = new HashSet<>();
      set.addAll(crlURLs);
      this.crlURLs = Collections.unmodifiableSet(set);
    }

    if (CollectionUtil.isEmpty(deltaCrlURLs)) {
      this.deltaCrlURLs = null;
    } else {
      Set<String> set = new HashSet<>();
      set.addAll(deltaCrlURLs);
      this.deltaCrlURLs = Collections.unmodifiableSet(set);
    }

    try {
      this.cert = X509Util.parseCert(certBytes);
    } catch (IOException e) {
      throw new CertificateException(e.getMessage(), e);
    }
    this.bcCert = Certificate.getInstance(certBytes);
    this.ski = X509Util.extractSKI(cert);
  } // constructor

  public Set<String> getCaIssuerURLs() {
    return caIssuerURLs;
  }

  public Set<String> getOcspURLs() {
    return ocspURLs;
  }

  public Set<String> getCrlURLs() {
    return crlURLs;
  }

  public Set<String> getDeltaCrlURLs() {
    return deltaCrlURLs;
  }

  public X509Certificate getCert() {
    return cert;
  }

  public byte[] getSubjectKeyIdentifier() {
    return Arrays.clone(ski);
  }

  public Certificate getBcCert() {
    return bcCert;
  }

}
