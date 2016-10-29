/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.pki.ca.server.impl;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class CaAuditConstants {

    public static final String APPNAME = "CA";

    public static final String MSGID_CA_routine = "CA_routine";

    public static final String MSGID_CA_mgmt = "CA_mgmt";

    public static final String NAME_CA = "CA";

    public static final String NAME_certprofile = "certprofile";

    public static final String NAME_crlNumber = "crlNumber";

    public static final String NAME_crlType = "crlType";

    public static final String NAME_expiredAt = "expiredAt";

    public static final String NAME_id = "id";

    public static final String NAME_invalidityTime = "invalidityTime";

    public static final String NAME_issuer = "issuer";

    public static final String NAME_message = "message";

    public static final String NAME_mid = "mid";

    public static final String NAME_nextUpdate = "nextUpdate";

    public static final String NAME_notBefore = "notBefore";

    public static final String NAME_notAfter = "notAfter";

    public static final String NAME_num = "num";

    public static final String NAME_PERF = "PERF";

    public static final String NAME_reason = "reason";

    public static final String NAME_reqType = "reqType";

    public static final String NAME_reqSubject = "reqSubject";

    public static final String NAME_requestor = "requestor";

    public static final String NAME_subject = "subject";

    public static final String NAME_SCEP_signature = "signature";

    public static final String NAME_SCEP_decryption = "decryption";

    public static final String NAME_SCEP_failureMessage = "failureMessage";

    public static final String NAME_SCEP_messageType = "messageType";

    public static final String NAME_SCEP_pkiStatus = "pkiStatus";

    public static final String NAME_SCEP_failInfo = "failInfo";

    public static final String NAME_SCEP_name = "name";

    public static final String NAME_SCEP_operation = "operation";

    public static final String NAME_serial = "serial";

    public static final String NAME_thisUpdate = "thisUpdate";

    public static final String NAME_tid = "tid";

    public static final String NAME_user = "user";

    // eventType
    public static final String TYPE_cleanup_CRL = "cleanup_CRL";

    public static final String TYPE_download_CRL = "download_CRL";

    public static final String TYPE_downlaod_CRLforNumber = "download_CRLforNumber";

    public static final String TYPE_get_systeminfo = "get_systeminfo";

    public static final String TYPE_gen_cert = "gen_cert";

    public static final String TYPE_gen_CRL = "gen_CRL";

    public static final String TYPE_regen_cert = "regenerate_cert";

    public static final String TYPE_revoke_CA = "revoke_CA";

    public static final String TYPE_remove_cert = "remove_cert";

    public static final String TYPE_remove_expiredCerts = "remove_expiredCerts";

    public static final String TYPE_revoke_suspendedCert = "revoke_suspendedCert";

    public static final String TYPE_revoke_suspendedCerts = "revoke_suspendedCerts";

    public static final String TYPE_revoke_cert = "revoke_cert";

    public static final String TYPE_unrevoke_CA = "unrevoke_CA";

    public static final String TYPE_unrevoke_CERT = "unrevoke_cert";

    public static final String TYPE_CMP_cr = "cr";

    public static final String TYPE_CMP_p10Cr = "p10Cr";

    public static final String TYPE_CMP_kur = "kur";

    public static final String TYPE_CMP_ccr = "ccr";

    public static final String TYPE_CMP_certConf = "certConf";

    public static final String TYPE_CMP_pkiConf = "pkiConf";

    public static final String TYPE_CMP_error = "error";

    public static final String TYPE_CMP_rr_revoke = "rr_revoke";

    public static final String TYPE_CMP_rr_unrevoke = "rr_unrevoke";

    public static final String TYPE_CMP_rr_remove = "rr_remove";

    public static final String TYPE_CMP_genm_currentCrl = "genm_currentCrl";

    public static final String TYPE_CMP_genm_genCrl = "genm_genCrl";

    public static final String TYPE_CMP_genm_crlForNumber = "genm_crlForNumber";

    public static final String TYPE_CMP_genm_cainfo = "genm_cainfo";

}
