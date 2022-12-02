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

package org.xipki.ca.api.mgmt;

import org.xipki.util.Args;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

import java.util.Arrays;
import java.util.List;

/**
 * Certificate Transparency Log control.
 * Currently it is only a placeholder. Need to be implemented in a later version.
 * @author Lijun Liao
 */

public class CtlogControl {

  /**
   * Whether CTLog is enabled: true or false.
   */
  public static final String KEY_ENABLED = "enabled";

  /**
   * ';'-separated URL of the CT Log servers.
   */
  public static final String KEY_SERVERS = "servers";

  /**
   * The name of SSL context.
   */
  public static final String KEY_SSLCONTEXT_NAME = "sslcontext.name";

  private boolean enabled;

  private String sslContextName;

  private List<String> servers;

  private ConfPairs confPairs;

  public CtlogControl(String conf) throws InvalidConfException {
    this(new ConfPairs(Args.notNull(conf, "conf")));
  }

  public CtlogControl(ConfPairs pairs) throws InvalidConfException {
    Args.notNull(pairs, "pairs");

    enabled = getBoolean(pairs, KEY_ENABLED, false);
    // normalize the pairs
    pairs.putPair(KEY_ENABLED, Boolean.toString(enabled));

    sslContextName = pairs.value(KEY_SSLCONTEXT_NAME);

    String serverList = pairs.value(KEY_SERVERS);
    servers = serverList == null ? null : Arrays.asList(serverList.split(";"));
    if (servers == null || servers.isEmpty()) {
      throw new InvalidConfException(KEY_SERVERS + " is not specified");
    }

    this.confPairs = pairs;
  } // constructor

  public CtlogControl(Boolean enabled, List<String> servers, String sslContextName) {
    Args.notEmpty(servers, "servers");

    ConfPairs pairs = new ConfPairs();
    this.enabled = enabled != null && enabled;
    pairs.putPair(KEY_ENABLED, Boolean.toString(this.enabled))
        .putPair(KEY_SERVERS, StringUtil.collectionAsString(servers, ";"));

    this.servers = servers;

    this.sslContextName = sslContextName;
    if (sslContextName != null) {
      pairs.putPair(KEY_SSLCONTEXT_NAME, sslContextName);
    }

    this.confPairs = pairs;
  } // constructor

  public boolean isEnabled() {
    return enabled;
  }

  public String getConf() {
    return getConfPairs().getEncoded();
  }

  public ConfPairs getConfPairs() {
    return confPairs;
  }

  public String getSslContextName() {
    return sslContextName;
  }

  public void setSslContextName(String sslContextName) {
    this.sslContextName = sslContextName;
  }

  public List<String> getServers() {
    return servers;
  }

  public void setServers(List<String> servers) {
    this.servers = servers;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public void setConf(ConfPairs confPairs) {
    this.confPairs = confPairs;
  }

  @Override
  public int hashCode() {
    return getConf().hashCode();
  }

  @Override
  public String toString() {
    return StringUtil.concatObjects(
        "  enabled: ", enabled,
        "\n  SSL context name: ", sslContextName,
        "\n  Servers: ", servers);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof CtlogControl)) {
      return false;
    }

    return confPairs.equals(((CtlogControl) obj).confPairs);
  }

  private static boolean getBoolean(ConfPairs pairs, String key, boolean defaultValue) {
    String str = pairs.value(key);
    boolean ret = StringUtil.isBlank(str) ? defaultValue : Boolean.parseBoolean(str);
    pairs.putPair(key, Boolean.toString(ret));
    return ret;
  } // method getBoolean

}
