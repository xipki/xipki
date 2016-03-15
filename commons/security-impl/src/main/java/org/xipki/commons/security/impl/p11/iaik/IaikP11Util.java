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

package org.xipki.commons.security.impl.p11.iaik;

import java.security.SecureRandom;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.p11.P11TokenException;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class IaikP11Util {

    private IaikP11Util() {
    }

    static byte[] generateKeyId(
            final Session session)
    throws P11TokenException {
        SecureRandom random = new SecureRandom();
        byte[] keyId = null;
        do {
            keyId = new byte[8];
            random.nextBytes(keyId);
        } while (idExists(session, keyId));

        return keyId;
    }

    static boolean idExists(
            final Session session, final byte[] keyId)
    throws P11TokenException {
        ParamUtil.requireNonNull("session", session);
        ParamUtil.requireNonNull("keyId", keyId);

        Key key = new Key();
        key.getId().setByteArrayValue(keyId);

        Object[] objects;
        try {
            session.findObjectsInit(key);
            objects = session.findObjects(1);
            session.findObjectsFinal();
            if (objects.length > 0) {
                return true;
            }

            X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
            cert.getId().setByteArrayValue(keyId);

            session.findObjectsInit(cert);
            objects = session.findObjects(1);
            session.findObjectsFinal();
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }

        return objects.length > 0;
    }

    static boolean labelExists(
            final Session session,
            final String keyLabel)
    throws P11TokenException {
        ParamUtil.requireNonNull("session", session);
        ParamUtil.requireNonBlank("keyLabel", keyLabel);
        Key key = new Key();
        key.getLabel().setCharArrayValue(keyLabel.toCharArray());

        Object[] objects;
        try {
            session.findObjectsInit(key);
            objects = session.findObjects(1);
            session.findObjectsFinal();
            if (objects.length > 0) {
                return true;
            }

            X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
            cert.getLabel().setCharArrayValue(keyLabel.toCharArray());

            session.findObjectsInit(cert);
            objects = session.findObjects(1);
            session.findObjectsFinal();
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }

        return objects.length > 0;
    }

    static String eraseSensitiveInfo(
            final String data) {
        ParamUtil.requireNonNull("data", data);
        int index = data.indexOf("password");
        if (index == -1) {
            return data;
        }

        if (index > 1 && data.charAt(index - 1) == '%') {
            return data.substring(0, index - 1);
        } else {
            return data.substring(0, index);
        }
    }

}
