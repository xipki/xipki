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

package org.xipki.pki.ca.client.api.dto;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;

/**
 * @author Lijun Liao
 * @since 2.0
 */

public class RevokeCertRequestEntryType extends IssuerSerialEntryType {

  private final int reason;

  private final Date invalidityDate;

  public RevokeCertRequestEntryType(
      final String id,
      final X509Certificate cert,
      final int reason,
      final Date invalidityDate) {
    this(id, X500Name.getInstance(cert.getIssuerX500Principal().getEncoded()),
        cert.getSerialNumber(), reason, invalidityDate);
  }

  public RevokeCertRequestEntryType(
      final String id,
      final X500Name issuer,
      final BigInteger serialNumber,
      final int reason,
      final Date invalidityDate) {
    super(id, issuer, serialNumber);

    if (!(reason >= 0 && reason <= 10 && reason != 7)) {
      throw new IllegalArgumentException("invalid reason: " + reason);
    }

    this.reason = reason;
    this.invalidityDate = invalidityDate;
  }

  public int getReason() {
    return reason;
  }

  public Date getInvalidityDate() {
    return invalidityDate;
  }

}
