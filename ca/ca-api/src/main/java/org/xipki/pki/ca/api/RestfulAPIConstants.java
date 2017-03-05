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

package org.xipki.pki.ca.api;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

// CHECKSTYLE:OFF
public class RestfulAPIConstants {

    public static final String CT_pkcs10 = "application/pkcs10";

    public static final String CT_pkix_crl = "application/pkix-crl";

    public static final String CT_pkix_cert = "application/pkix-cert";

    public static final String HEADER_PKISTATUS = "X-xipki-pkistatus";

    public static final String PKISTATUS_accepted = "accepted";

    public static final String PKISTATUS_rejection = "rejection";

    public static final String PKISTATUS_waiting = "waiting";

    public static final String HEADER_STATUS_String = "X-xipki-status-string";

    public static final String HEADER_failInfo = "X-xipki-fail-info";

    public static final String FAILINFO_badAlg = "badAlg";

    public static final String FAILINFO_badMessageCheck = "badMessageCheck";

    public static final String FAILINFO_badRequest = "badRequest";

    public static final String FAILINFO_badCertId = "badCertId";

    public static final String FAILINFO_badPOP = "badPOP";

    public static final String FAILINFO_certRevoked = "certRevoked";

    public static final String FAILINFO_unacceptedExtension = "unacceptedExtension";

    public static final String FAILINFO_badCertTemplate = "badCertTemplate";

    public static final String FAILINFO_notAuthorized = "notAuthorized";

    public static final String FAILINFO_systemUnavail = "systemUnavail";

    public static final String FAILINFO_systemFailure = "systemFailure";

    public static final String CMD_cacert = "cacert";

    public static final String CMD_revoke_cert = "revoke-cert";

    public static final String CMD_delete_cert = "delete-cert";

    public static final String CMD_enroll_cert = "enroll-cert";

    public static final String CMD_crl = "crl";

    public static final String CMD_new_crl = "new-crl";

    public static final String PARAM_profile = "profile";

    public static final String PARAM_reason = "reason";

    public static final String PARAM_not_before = "not-before";

    public static final String PARAM_not_after = "not-after";

    public static final String PARAM_invalidity_time = "invalidity-time";

    public static final String PARAM_crl_number = "crl-number";

    public static final String PARAM_ca_sha1 = "ca-sha1";

    public static final String PARAM_serial_number = "serial-number";

}
