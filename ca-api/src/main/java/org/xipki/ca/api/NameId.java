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

package org.xipki.ca.api;

import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

public class NameId {

  private Integer id;

  private final String name;

  public NameId(Integer id, String name) {
    this.id = id;
    this.name = ParamUtil.requireNonBlank("name", name).toLowerCase();
  }

  public void setId(Integer id) {
    this.id = id;
  }

  public Integer id() {
    return id;
  }

  public String name() {
    return name;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof NameId)) {
      return false;
    }

    NameId other = (NameId) obj;

    return CompareUtil.equalsObject(id, other.id) && name.equals(other.name);
  }

  @Override
  public int hashCode() {
    int ret = name.hashCode();
    if (id != null) {
      ret += 37 * id;
    }
    return ret;
  }

  @Override
  public String toString() {
    return StringUtil.concatObjects("(id=", id, ", name=", name, ")");

  }

}
