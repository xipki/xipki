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

import org.xipki.util.Args;
import org.xipki.util.ConfPairs;
import org.xipki.util.InvalidConfException;
import org.xipki.util.StringUtil;

/**
 * Certificate Transparency Log control.
 * Currently is only a place holder. Need to be implemented in a later version.
 * @author Lijun Liao
 */

public class CtLogControl {

  public static final String KEY_ENABLED = "enabled";

  private final boolean enabled;

  private final String conf;

  public CtLogControl(String conf) throws InvalidConfException {
    ConfPairs pairs = new ConfPairs(Args.notNull(conf, "conf"));
    this.enabled = getBoolean(pairs, KEY_ENABLED, false);
    this.conf = pairs.getEncoded();
  } // constructor

  public CtLogControl(Boolean enabled)
      throws InvalidConfException {
    ConfPairs pairs = new ConfPairs();

    this.enabled = (enabled == null) ? false : enabled;
    pairs.putPair(KEY_ENABLED, Boolean.toString(this.enabled));

    this.conf = pairs.getEncoded();
  } // constructor

  public boolean isEnabled() {
    return enabled;
  }

  public String getConf() {
    return conf;
  }

  @Override
  public int hashCode() {
    return conf.hashCode();
  }

  @Override
  public String toString() {
    return toString(false);
  }

  public String toString(boolean verbose) {
    return StringUtil.concatObjects(
        "  enalbed: ", enabled);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof CtLogControl)) {
      return false;
    }

    return conf.equals(((CtLogControl) obj).conf);
  }

  private static boolean getBoolean(ConfPairs pairs, String key, boolean defaultValue) {
    String str = pairs.value(key);
    boolean ret = StringUtil.isBlank(str) ? defaultValue : Boolean.parseBoolean(str);
    pairs.putPair(key, Boolean.toString(ret));
    return ret;
  }

}
