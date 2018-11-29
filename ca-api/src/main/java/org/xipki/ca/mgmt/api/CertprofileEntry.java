/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.mgmt.api;

import org.xipki.ca.api.NameId;
import org.xipki.util.CompareUtil;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertprofileEntry {

  private NameId ident;

  private String type;

  private String conf;

  private boolean faulty;

  // For the deserialization only
  @SuppressWarnings("unused")
  private CertprofileEntry() {
  }

  public CertprofileEntry(NameId ident, String type, String conf) {
    this.ident = Args.notNull(ident, "ident");
    this.type = Args.toNonBlankLower(type, "type");
    this.conf = conf;
    if ("all".equalsIgnoreCase(ident.getName()) || "null".equalsIgnoreCase(ident.getName())) {
      throw new IllegalArgumentException("certificate profile name may not be 'all' and 'null'");
    }
  }

  public void setIdent(NameId ident) {
    if ("all".equalsIgnoreCase(ident.getName()) || "null".equalsIgnoreCase(ident.getName())) {
      throw new IllegalArgumentException("certificate profile name may not be 'all' and 'null'");
    }
    this.ident = Args.notNull(ident, "ident");
  }

  public void setType(String type) {
    this.type = Args.toNonBlankLower(type, "type");
  }

  public void setConf(String conf) {
    this.conf = conf;
  }

  public NameId getIdent() {
    return ident;
  }

  public String getType() {
    return type;
  }

  public String getConf() {
    return conf;
  }

  public boolean isFaulty() {
    return faulty;
  }

  public void setFaulty(boolean faulty) {
    this.faulty = faulty;
  }

  @Override
  public String toString() {
    return toString(false);
  }

  public String toString(boolean verbose) {
    boolean bo = (verbose || conf == null || conf.length() < 301);
    return StringUtil.concatObjectsCap(200, "id: ", ident.getId(), "\nname: ", ident.getName(),
        "\nfaulty: ", faulty, "\ntype: ", type, "\nconf: ",
        (bo ? conf : StringUtil.concat(conf.substring(0, 297), "...")));
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if  (!(obj instanceof CertprofileEntry)) {
      return false;
    }

    return equals((CertprofileEntry) obj, false);
  }

  public boolean equals(CertprofileEntry obj, boolean ignoreId) {
    if (!ident.equals(obj.ident, ignoreId)) {
      return false;
    }

    if (!type.equals(obj.type)) {
      return false;
    }

    if (!CompareUtil.equalsObject(conf, obj.conf)) {
      return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    return ident.hashCode();
  }

}
