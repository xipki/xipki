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

/**
 * Keypair generation entry.
 * @author Lijun Liao
 * @since 6.0.0
 */

public class KeypairGenEntry extends MgmtEntry {

  /**
   * Specify how many parallel keypair generation processes are allowed.
   * Default to 10.
   */
  public static final String KEY_PARALLELISM = "parallelism";

  public static final String TYPE_SOFT = "soft";

  public static final String TYPE_PKCS11 = "pkcs11";

  public static final String TYPE_DATABASE = "database";

  /**
   * PKCS#11 module.
   */
  public static final String KEY_MODULE  = "module";

  /**
   * PKCS#11 slot index.
   */
  public static final String KEY_SLOT    = "slot";

  /**
   * PKCS#11 slot id.
   */
  public static final String KEY_SLOT_ID = "slot-id";

  /**
   * Datasource for the type database.
   */
  public static final String KEY_DATASOURCE = "datasource";

  /**
   * The key used to decrypt the saved keypair, for the type database.
   * It is the hex-encoded key. For security, it should be encrypted by the
   * master password.
   */
  public static final String KEY_ENC_KEY = "enc-key";

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
          sb.append(new ConfPairs(conf).toStringOmitSensitive("key"));
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
