/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.ca.api.mgmt;

import org.xipki.security.CrlReason;
import org.xipki.util.Args;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;
import org.xipki.util.Validity;
import org.xipki.util.Validity.Unit;

/**
 * Revoke suspended certificate control.
 *
 * <p>Example configuration
 *<pre>
 * enabled=&lt;true|false&gt;, \
 *   [targetReason=&lt;CRL reason&gt;,\
 *   unchangedSince=&lt;duration&gt;]
 *</pre>
 * where duration is of format &lt;n&gt;h, &lt;n&gt;d, &lt;n&gt;y.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RevokeSuspendedControl {

  public static final String KEY_ENABLED = "enabled";

  public static final String KEY_REVOCATION_REASON = "targetReason";

  public static final String KEY_UNCHANGED_SINCE = "unchangedSince";

  private final boolean enabled;

  private final CrlReason targetReason;

  private final Validity unchangedSince;

  public RevokeSuspendedControl(String conf) {
    this(new ConfPairs(conf));
  }

  public RevokeSuspendedControl(ConfPairs conf) {
    Args.notNull(conf, "conf");

    this.enabled = getBoolean(conf, KEY_ENABLED, false);
    String str = conf.value(KEY_REVOCATION_REASON);
    this.targetReason = (str == null)
        ? CrlReason.CESSATION_OF_OPERATION : CrlReason.forNameOrText(str);

    str = conf.value(KEY_UNCHANGED_SINCE);
    this.unchangedSince = (str == null)
        ? new Validity(15, Unit.DAY) : Validity.getInstance(str);
  }

  public RevokeSuspendedControl(boolean enabled) {
    this(enabled, null, null);
  }

  public RevokeSuspendedControl(boolean enabled, CrlReason targetReason, Validity unchangedSince) {
    this.enabled = enabled;
    this.targetReason = targetReason == null ? CrlReason.CESSATION_OF_OPERATION : targetReason;
    this.unchangedSince = unchangedSince == null ? new Validity(15, Unit.DAY) : unchangedSince;

    switch (this.targetReason) {
      case AFFILIATION_CHANGED:
      case CESSATION_OF_OPERATION:
      case KEY_COMPROMISE:
      case PRIVILEGE_WITHDRAWN:
      case SUPERSEDED:
      case UNSPECIFIED:
        break;
      default:
        throw new IllegalArgumentException("invalid targetReason " + targetReason);
    }
  } // constructor

  public boolean isEnabled() {
    return enabled;
  }

  public CrlReason getTargetReason() {
    return targetReason;
  }

  public Validity getUnchangedSince() {
    return unchangedSince;
  }

  @Override
  public String toString() {
    return StringUtil.concatObjects(
        "  enabled: ", enabled,
        "\n  target reason: ", targetReason,
        "\n  unchanged since: ", unchangedSince);
  }

  public String getConf() {
    ConfPairs pairs = new ConfPairs();
    pairs.putPair(KEY_ENABLED, Boolean.toString(enabled));
    pairs.putPair(KEY_REVOCATION_REASON, targetReason.getDescription());
    pairs.putPair(KEY_UNCHANGED_SINCE, unchangedSince.toString());
    return pairs.getEncoded();
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof RevokeSuspendedControl)) {
      return false;
    }

    RevokeSuspendedControl obj2 = (RevokeSuspendedControl) obj;
    return enabled == obj2.enabled
        && (targetReason == obj2.targetReason)
        && (unchangedSince != obj2.unchangedSince);
  }

  private static boolean getBoolean(ConfPairs pairs, String key, boolean defaultValue) {
    String str = pairs.value(key);
    boolean ret = StringUtil.isBlank(str) ? defaultValue : Boolean.parseBoolean(str);
    pairs.putPair(key, Boolean.toString(ret));
    return ret;
  }

}
