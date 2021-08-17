/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.server;

/**
 * Constants used to identify the audit event.
 *
 * @author Lijun Liao
 * @since 3.0.1
 */

public class CaAuditConstants {

  public static final class Scep {
    public static final String NAME_decryption = "decryption";

    public static final String NAME_fail_info = "fail_info";

    public static final String NAME_failure_message = "failure_message";

    public static final String NAME_message_type = "message_type";

    public static final String NAME_name = "name";

    public static final String NAME_pki_status = "pki_status";

    public static final String NAME_operation = "operation";

    public static final String NAME_signature = "signature";
  }

  public static final class Cmp {

    public static final String TYPE_ccr = "ccr";

    public static final String TYPE_certConf = "cert_conf";

    public static final String TYPE_ir = "ir";

    public static final String TYPE_cr = "cr";

    public static final String TYPE_error = "error";

    public static final String TYPE_genm_cacertchain = "genm_cacertchain";

    public static final String TYPE_genm_cainfo = "genm_cainfo";

    public static final String TYPE_genm_crl4number = "genm_crl4number";

    public static final String TYPE_genm_current_crl = "genm_current_crl";

    public static final String TYPE_genm_gen_crl = "genm_gen_crl";

    public static final String TYPE_kur = "kur";

    public static final String TYPE_p10cr = "p10cr";

    public static final String TYPE_pkiconf = "pkiconf";

    public static final String TYPE_rr_remove = "rr_remove";

    public static final String TYPE_rr_revoke = "rr_revoke";

    public static final String TYPE_rr_unrevoke = "rr_unrevoke";

  }

  public static final String APPNAME = "ca";

  public static final String MSGID_ca_routine = "ca_routine";

  public static final String MSGID_ca_mgmt = "ca_mgmt";

  public static final String MSGID_scep = "scep";

  public static final String NAME_ca = "ca";

  public static final String NAME_certprofile = "certprofile";

  public static final String NAME_crl_number = "crl_number";

  public static final String NAME_basecrl_number = "basecrl_number";

  public static final String NAME_crl_type = "crl_type";

  public static final String NAME_expired_at = "expired_at";

  public static final String NAME_invalidity_time = "invalidity_time";

  public static final String NAME_issuer = "issuer";

  public static final String NAME_message = "message";

  public static final String NAME_mid = "mid";

  public static final String NAME_next_update = "next_update";

  public static final String NAME_not_after = "not_after";

  public static final String NAME_not_before = "not_before";

  public static final String NAME_num = "num";

  public static final String NAME_perf = "perf";

  public static final String NAME_reason = "reason";

  public static final String NAME_req_type = "req_type";

  public static final String NAME_req_subject = "req_subject";

  public static final String NAME_requestor = "requestor";

  public static final String NAME_serial = "serial";

  public static final String NAME_tid = "tid";

  public static final String NAME_subject = "subject";

  // eventType
  public static final String TYPE_cleanup_crl = "cleanup_crl";

  public static final String TYPE_downlaod_crl4number = "download_crl4number";

  public static final String TYPE_download_crl = "download_crl";

  public static final String TYPE_gen_cert = "gen_cert";

  public static final String TYPE_gen_crl = "gen_crl";

  public static final String TYPE_unrevoke_cert = "unrevoke_cert";

  public static final String TYPE_remove_cert = "remove_cert";

  public static final String TYPE_remove_expired_certs = "remove_expired_certs";

  public static final String TYPE_revoke_cert = "revoke_cert";

  public static final String TYPE_revoke_suspendedCert = "revoke_suspended_cert";

}
