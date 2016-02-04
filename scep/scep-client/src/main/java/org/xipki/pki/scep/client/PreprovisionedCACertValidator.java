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

package org.xipki.pki.scep.client;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.xipki.pki.scep.crypto.HashAlgoType;
import org.xipki.pki.scep.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public final class PreprovisionedCACertValidator implements CACertValidator {

  private final Set<String> fpOfCerts;

  public PreprovisionedCACertValidator(
      final X509Certificate cert) {
    ParamUtil.assertNotNull("cert", cert);
    fpOfCerts = new HashSet<String>(1);
    String hexFp;
    try {
      hexFp = HashAlgoType.SHA256.hexDigest(cert.getEncoded());
    } catch (CertificateEncodingException e) {
      throw new IllegalArgumentException(
          "at least one of the certificate could not be encoded");
    }
    fpOfCerts.add(hexFp);
  }

  public PreprovisionedCACertValidator(
      final Set<X509Certificate> certs) {
    ParamUtil.assertNotEmpty("certs", certs);
    fpOfCerts = new HashSet<String>(certs.size());
    for (X509Certificate m : certs) {
      String hexFp;
      try {
        hexFp = HashAlgoType.SHA256.hexDigest(m.getEncoded());
      } catch (CertificateEncodingException e) {
        throw new IllegalArgumentException(
            "at least one of the certificate could not be encoded");
      }
      fpOfCerts.add(hexFp);
    }
  }

  @Override
  public boolean isTrusted(
      final X509Certificate cert) {
    String hextFp;
    try {
      hextFp = HashAlgoType.SHA256.hexDigest(cert.getEncoded());
    } catch (CertificateEncodingException e) {
      return false;
    }
    return fpOfCerts.contains(hextFp);
  }

}
