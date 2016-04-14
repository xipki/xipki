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
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.dbtool.diffdb;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EjbcaConstants {

    /**
     * Certificate doesn't belong to anyone.
     */
    public static final int CERT_UNASSIGNED = 0;

    /**
     * Assigned, but not yet active.
     */
    public static final int CERT_INACTIVE = 10;

    /**
     * Certificate is active and assigned.
     */
    public static final int CERT_ACTIVE = 20;

    /**
     * Certificate is temporarily blocked (reversible).
     */
    public static final int CERT_TEMP_REVOKED = 30;

    /**
     * Certificate is permanently blocked (terminated).
     */
    public static final int CERT_REVOKED = 40;

    /**
     * Certificate is expired.
     */
    public static final int CERT_EXPIRED = 50;

    /**
     * Certificate is expired and kept for archive purpose.
     */
    public static final int CERT_ARCHIVED = 60;

    private EjbcaConstants() {
    }

}
