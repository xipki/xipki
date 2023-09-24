// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.util.Args;
import org.xipki.util.CompareUtil;
import org.xipki.util.ConfPairs;

import java.util.Arrays;
import java.util.Collections;

/**
 * Keypair generation entry.
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class KeypairGenEntry extends MgmtEntry {

  private String name;

  private String type;

  private String conf;

  private boolean faulty;

  // For JSON deserializer only.
  private KeypairGenEntry() {
  }

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

  public void faulty(boolean faulty) {
    this.faulty = faulty;
  }

  public boolean faulty() {
    return faulty;
  }

  @Override
  public String toString() {
    return toString(true);
  }

  public String toString(boolean ignoreSensitiveInfo) {
    StringBuilder sb = new StringBuilder(1000);
    sb.append("name:   ").append(name).append('\n');
    sb.append("faulty: ").append(faulty()).append('\n');
    sb.append("type:   ").append(type).append('\n');
    sb.append("conf:   ");
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
