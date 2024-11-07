// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

/**
 * Constants used to identify the audit event.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CaAuditConstants {

  public static final String APPNAME = "ca";

  public static final String NAME_ca = "ca";

  public static final String NAME_certprofile = "certprofile";

  public static final String NAME_crl_number = "crl_number";

  public static final String NAME_basecrl_number = "basecrl_number";

  public static final String NAME_crl_type = "crl_type";

  public static final String NAME_expired_at = "expired_at";

  public static final String NAME_invalidity_time = "invalidity_time";

  public static final String NAME_issuer = "issuer";

  public static final String NAME_message = "message";

  public static final String NAME_next_update = "next_update";

  public static final String NAME_not_after = "not_after";

  public static final String NAME_not_before = "not_before";

  public static final String NAME_num = "num";

  public static final String NAME_reason = "reason";

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

  public static final String TYPE_regen_cert = "regen_cert";

  public static final String TYPE_gen_crl = "gen_crl";

  public static final String TYPE_unsuspend_cert = "unsuspend_cert";

  public static final String TYPE_suspend_cert = "suspend_cert";
  public static final String TYPE_remove_cert = "remove_cert";

  public static final String TYPE_remove_expired_certs = "remove_expired_certs";

  public static final String TYPE_revoke_cert = "revoke_cert";

  public static final String TYPE_revoke_ca = "revoke_ca";

  public static final String TYPE_suspend_ca = "revoke_ca";

  public static final String TYPE_unsuspend_ca = "unrevoke_ca";

  public static final String TYPE_revoke_suspendedCert = "revoke_suspended_cert";

}
