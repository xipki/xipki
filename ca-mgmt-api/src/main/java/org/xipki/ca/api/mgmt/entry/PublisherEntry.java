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

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.NameId;
import org.xipki.util.Args;
import org.xipki.util.CompareUtil;
import org.xipki.util.StringUtil;

/**
 * Management Entry Publisher.
 * @author Lijun Liao
 *
 */

public class PublisherEntry extends MgmtEntry {

  private NameId ident;

  private String type;

  private String conf;

  private boolean faulty;

  // For the deserialization only
  @SuppressWarnings("unused")
  private PublisherEntry() {
  }

  public PublisherEntry(NameId ident, String type, String conf) {
    this.ident = Args.notNull(ident, "ident");
    this.type = Args.toNonBlankLower(type, "type");
    this.conf = conf;
  }

  public void setIdent(NameId ident) {
    this.ident = Args.notNull(ident, "ident");
  }

  public NameId getIdent() {
    return ident;
  }

  public void setType(String type) {
    this.type = Args.toNonBlankLower(type, "type");
  }

  public String getType() {
    return type;
  }

  public void setConf(String conf) {
    this.conf = conf;
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
    return StringUtil.concatObjectsCap(200, "id: ", ident.getId(), "\nname: ", ident.getName(),
        "\nfaulty: ", faulty, "\ntype: ", type, "\nconf: ", conf);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof PublisherEntry)) {
      return false;
    }

    return equals((PublisherEntry) obj, false);
  }

  public boolean equals(PublisherEntry obj, boolean ignoreId) {
    return (obj != null)
        && ident.equals(obj.ident, ignoreId)
        && type.equals(obj.type)
        && CompareUtil.equalsObject(conf, obj.conf);
  }

  @Override
  public int hashCode() {
    return ident.hashCode();
  }

}
