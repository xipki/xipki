/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.api;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

// CHECKSTYLE:OFF
public class RestAPIConstants {

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
