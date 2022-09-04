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

package org.xipki.ca.api.mgmt.entry;

import org.xipki.util.Args;
import org.xipki.util.CompareUtil;
import org.xipki.util.ConfPairs;

import java.util.Arrays;
import java.util.Collections;

/**
 * Keypair generation entry.
 * @author Lijun Liao
 * @since 6.0.0
 */

public class KeypairGenEntry extends MgmtEntry {

  private final String name;

  private final String type;

  private final String conf;

  private boolean faulty;

  public KeypairGenEntry(String name, String type, String conf) {
    this.name = Args.toNonBlankLower(name, "name");
    this.type = Args.toNonBlankLower(type, "type");
    this.conf = conf;
  }

  public String getName() {
    return name;
  }

  public String getType() {
    return type;
  }

  public String getConf() {
    return conf;
  }

  public void setFaulty(boolean faulty) {
    this.faulty = faulty;
  }

  public boolean isFaulty() {
    return faulty;
  }

  @Override
  public String toString() {
    return toString(true);
  }

  public String toString(boolean ignoreSensitiveInfo) {
    StringBuilder sb = new StringBuilder(1000);
    sb.append("name: ").append(name).append('\n');
    sb.append("faulty: ").append(isFaulty()).append('\n');
    sb.append("type: ").append(type).append('\n');
    sb.append("conf: ");
    if (conf == null) {
      sb.append("null");
    } else {
      if (ignoreSensitiveInfo) {
        try {
          sb.append(new ConfPairs(conf).toStringOmitSensitive(
              Arrays.asList("key", "password"), Collections.singletonList("keyspec")));
        } catch (Exception ex) {
          sb.append(conf);
        }
      } else {
        sb.append(conf);
      }
    }
    sb.append('\n');
    return sb.toString();
  } // method toString(boolean, boolean)

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof KeypairGenEntry)) {
      return false;
    }

    KeypairGenEntry objB = (KeypairGenEntry) obj;
    return name.equals(objB.name)
        && type.equals(objB.type)
        && CompareUtil.equalsObject(conf, objB.conf);
  } // method equals

  @Override
  public int hashCode() {
    return name.hashCode();
  }

}
