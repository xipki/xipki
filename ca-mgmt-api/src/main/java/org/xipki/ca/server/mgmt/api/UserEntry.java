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

package org.xipki.ca.server.mgmt.api;

import org.xipki.ca.api.NameId;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class UserEntry {

  private final NameId ident;

  private final boolean active;

  private final String hashedPassword;

  public UserEntry(NameId ident, boolean active, String hashedPassword) throws CaMgmtException {
    this.ident = ParamUtil.requireNonNull("ident", ident);
    this.active = active;
    this.hashedPassword = ParamUtil.requireNonBlank("hashedPassword", hashedPassword);
  }

  public NameId ident() {
    return ident;
  }

  public boolean active() {
    return active;
  }

  public String hashedPassword() {
    return hashedPassword;
  }

  @Override
  public String toString() {
    return StringUtil.concatObjectsCap(200, "id: ", ident.id(), "\nname: ", ident.name(),
        "\nactive: ", active, "\npassword: *****\n");
  }

}
