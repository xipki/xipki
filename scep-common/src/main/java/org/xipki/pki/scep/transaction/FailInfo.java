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

package org.xipki.pki.scep.transaction;

/**
 * @author Lijun Liao
 * @since 2.0
 */

public enum FailInfo {

  /**
   * Unrecognized or unsupported algorithm identifier
   */
  badAlg (0),

  /**
   * integrity check failed
   */
  badMessageCheck (1),

  /**
   * transaction not permitted or supported
   */
  badRequest (2),

  /**
   * The signingTime attribute from the CMS, authenticatedAttributes was not sufficiently
   * close to the system time
   */
  badTime (3),

  /**
   * No certificate could be identified matching the provided criteria
   */
  badCertId (4);

  private final int code;

  private FailInfo(
      final int code) {
    this.code = code;
  }

  public int getCode() {
    return code;
  }

  public static FailInfo valueForCode(
      final int code) {
    for (FailInfo m : values()) {
      if (m.code == code) {
        return m;
      }
    }
    return null;
  }

}
