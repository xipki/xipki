// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.extra.misc.CompareUtil;
import org.xipki.util.misc.StringUtil;

import java.util.Arrays;
import java.util.Collections;

/**
 * Keypair generation entry.
 * @author Lijun Liao (xipki)
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

  public String name() {
    return StringUtil.lowercase(name);
  }

  public String type() {
    return type;
  }

  public String conf() {
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
              Arrays.asList("key", "password"),
              Collections.singletonList("keyspec")));
        } catch (Exception ex) {
          sb.append(conf);
        }
      } else {
        sb.append(conf);
      }
    }
    sb.append('\n');
    return sb.toString();
  }

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
        && CompareUtil.equals(conf, objB.conf);
  } // method equals

  @Override
  public int hashCode() {
    return name.hashCode();
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("name", name).put("type", type).put("conf", conf);
  }

  public static KeypairGenEntry parse(JsonMap json) throws CodecException {
    return new KeypairGenEntry(json.getNnString("name"),
        json.getNnString("type"), json.getString("conf"));
  }

}
