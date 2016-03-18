/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.security.api.p11;

import java.util.List;
import java.util.Set;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface P11Slot {
    // FIXME: the implementation shall contain a complete map from id to label for all objects which
    // are not considered already and consider them in the getP11KeyIdFor*().
    String getModuleName();

    P11SlotIdentifier getSlotId();

    List<P11KeyIdentifier> getKeyIdentifiers()
    throws P11TokenException;

    boolean hasIdentity(
            final P11KeyIdentifier keyId);

    void close();

    Set<Long> getMechanisms();

    boolean supportsMechanism(
            final long mechanism);

    void assertMechanismSupported(
            final long mechanism)
    throws P11UnsupportedMechanismException;

    P11Identity getIdentity(
            final P11KeyIdentifier keyId)
    throws P11UnknownEntityException;

    void refresh()
    throws P11TokenException;

    P11KeyIdentifier getKeyIdForId(
            byte[] keyId)
    throws P11UnknownEntityException;

    P11KeyIdentifier getKeyIdForLabel(
            String keyLabel)
    throws P11UnknownEntityException;

}
