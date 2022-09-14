/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.ca.sdk;

/**
 * REST API constants.
 *
 * @author Lijun Liao
 * @since 2.1.0
 */

public class SdkConstants {

  public static final String CMD_health = "health";

  public static final String CMD_cacert = "cacert";

  public static final String CMD_cacerts = "cacerts";

  public static final String CMD_profileinfo = "profileinfo";

  public static final String CMD_revoke_cert = "revoke_cert";

  public static final String CMD_suspend_cert = "suspend_cert";

  public static final String CMD_unsuspend_cert = "unsuspend_cert";

  public static final String CMD_remove_cert = "remove_cert";

  public static final String CMD_enroll = "enroll";

  public static final String CMD_enroll_cross = "enroll_cross";

  public static final String CMD_reenroll = "reenroll";

  public static final String CMD_confirm_enroll = "confirm_enroll";

  public static final String CMD_poll_cert = "poll_cert";

  public static final String CMD_get_cert = "get_cert";

  public static final String CMD_crl = "crl";

  public static final String CMD_gen_crl = "gen_crl";

  public static final String CMD_revoke_pending_cert = "revoke_pending_cert";

}
