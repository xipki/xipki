/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.commons.security.pkcs11.proxy;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11ProxyConstants {

    public static final short VERSION_V1_0             = 0x0100;

    /* Return Code */
    public static final short RC_SUCCESS               = 0x0000;

    public static final short RC_INTERNAL_ERROR        = 0x0001;

    public static final short RC_UNSUPPORTED_VERSION   = 0x0002;

    public static final short RC_UNSUPPORTED_ACTION    = 0x0003;

    public static final short RC_BAD_REQUEST           = 0x0004;

    public static final short RC_UNKNOWN_MODULE        = 0x0101;

    public static final short RC_UNKNOWN_ENTITY        = 0x0102;

    public static final short RC_DUPLICATE_ENTITY      = 0x0103;

    public static final short RC_UNSUPPORTED_MECHANISM = 0x0104;

    public static final short RC_P11_TOKENERROR        = 0x0105;

    /* Action */
    /**
     * Will be used in the response if the server cannot detect the action.
     */
    public static final short ACTION_NOPE              = 0x0000;

    public static final short ACTION_GET_SERVER_CAPS   = 0x0001;

    public static final short ACTION_GET_PUBLICKEY     = 0x0101;

    public static final short ACTION_GET_CERT          = 0x0102;

    public static final short ACTION_GET_SLOT_IDS      = 0x0103;

    public static final short ACTION_GET_IDENTITY_IDS  = 0x0104;

    public static final short ACTION_GET_CERT_IDS      = 0x0105;

    public static final short ACTION_GET_MECHANISMS    = 0x0106;

    public static final short ACTION_SIGN              = 0x0120;

    public static final short ACTION_GEN_KEYPAIR_RSA   = 0x0130;

    public static final short ACTION_GEN_KEYPAIR_DSA   = 0x0131;

    public static final short ACTION_GEN_KEYPAIR_EC    = 0x0133;

    public static final short ACTION_DIGEST_SECRETKEY  = 0x0134;

    public static final short ACTION_GEN_SECRET_KEY    = 0x0135;

    public static final short ACTION_CREATE_SECRET_KEY = 0x0136;

    public static final short ACTION_ADD_CERT          = 0x0140;

    public static final short ACTION_REMOVE_IDENTITY   = 0x0141;

    public static final short ACTION_REMOVE_CERTS      = 0x0142;

    public static final short ACTION_UPDATE_CERT       = 0x0143;

    public static final short ACTION_REMOVE_OBJECTS    = 0x0144;

    private static final Map<Short, String> rcMap;

    private static final Map<Short, String> actionMap;

    static {
        // RC
        rcMap = new HashMap<>();
        rcMap.put(RC_BAD_REQUEST,              "RC_BAD_REQUEST");
        rcMap.put(RC_DUPLICATE_ENTITY,         "RC_DUPLICATE_ENTITY");
        rcMap.put(RC_INTERNAL_ERROR,           "RC_INTERNAL_ERROR");
        rcMap.put(RC_P11_TOKENERROR,           "RC_P11_TOKENERROR");
        rcMap.put(RC_SUCCESS,                  "RC_SUCCESS");
        rcMap.put(RC_UNKNOWN_ENTITY,           "RC_UNKNOWN_ENTITY");
        rcMap.put(RC_UNKNOWN_MODULE,           "RC_UNKNOWN_MODULE");
        rcMap.put(RC_UNSUPPORTED_ACTION,       "RC_UNSUPPORTED_ACTION");
        rcMap.put(RC_UNSUPPORTED_MECHANISM,    "RC_UNSUPPORTED_MECHANISM");
        rcMap.put(RC_UNSUPPORTED_VERSION,      "RC_UNSUPPORTED_VERSION");

        // action
        actionMap = new HashMap<>();
        actionMap.put(ACTION_ADD_CERT,         "ACTION_ADD_CERT");
        actionMap.put(ACTION_GEN_KEYPAIR_DSA,  "ACTION_GEN_KEYPAIR_DSA");
        actionMap.put(ACTION_GEN_KEYPAIR_EC,   "ACTION_GEN_KEYPAIR_EC");
        actionMap.put(ACTION_GEN_KEYPAIR_RSA,  "ACTION_GEN_KEYPAIR_RSA");
        actionMap.put(ACTION_GET_CERT,         "ACTION_GET_CERT");
        actionMap.put(ACTION_GET_CERT_IDS,     "ACTION_GET_CERT_IDS");
        actionMap.put(ACTION_GET_IDENTITY_IDS, "ACTION_GET_IDENTITY_IDS");
        actionMap.put(ACTION_GET_MECHANISMS,   "ACTION_GET_MECHANISMS");
        actionMap.put(ACTION_GET_PUBLICKEY,    "ACTION_GET_PUBLICKEY");
        actionMap.put(ACTION_GET_SERVER_CAPS,  "ACTION_GET_SERVER_CAPS");
        actionMap.put(ACTION_GET_SLOT_IDS,     "ACTION_GET_SLOT_IDS");
        actionMap.put(ACTION_NOPE,             "ACTION_NOPE");
        actionMap.put(ACTION_REMOVE_CERTS,     "ACTION_REMOVE_CERTS");
        actionMap.put(ACTION_REMOVE_IDENTITY,  "ACTION_REMOVE_IDENTITY");
        actionMap.put(ACTION_REMOVE_OBJECTS,   "ACTION_REMOVE_OBJECTS");
        actionMap.put(ACTION_SIGN,             "ACTION_SIGN");
        actionMap.put(ACTION_UPDATE_CERT,      "ACTION_UPDATE_CERT");
    }

    private P11ProxyConstants() {
    }

    public static String getReturnCodeName(short rc) {
        String name = rcMap.get(rc);
        return (name == null) ? Short.toString(rc) : name;
    }

    public static String getActionName(short action) {
        String name = actionMap.get(action);
        return (name == null) ? Short.toString(action) : name;
    }

}
