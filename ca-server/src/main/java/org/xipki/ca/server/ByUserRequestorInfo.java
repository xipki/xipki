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

package org.xipki.ca.server;

import java.util.Set;

import org.xipki.ca.api.InsuffientPermissionException;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.MgmtEntry;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

public class ByUserRequestorInfo implements RequestorInfo {

  private final NameId ident;

  private final MgmtEntry.CaHasUser caHasUser;

  public ByUserRequestorInfo(NameId ident, MgmtEntry.CaHasUser caHasUser) {
    this.ident = Args.notNull(ident, "ident");
    this.caHasUser = Args.notNull(caHasUser, "caHasUser");
  }

  @Override
  public NameId getIdent() {
    return ident;
  }

  @Override
  public boolean isRa() {
    return false;
  }

  public int getUserId() {
    return caHasUser.getUserIdent().getId();
  }

  public MgmtEntry.CaHasUser getCaHasUser() {
    return caHasUser;
  }

  @Override
  public boolean isCertprofilePermitted(String certprofile) {
    Set<String> profiles = caHasUser.getProfiles();
    if (CollectionUtil.isEmpty(profiles)) {
      return false;
    }

    return profiles.contains("all") || profiles.contains(certprofile.toLowerCase());
  }

  @Override
  public boolean isPermitted(int permission) {
    return PermissionConstants.contains(caHasUser.getPermission(), permission);
  }

  @Override
  public void assertCertprofilePermitted(String certprofile) throws InsuffientPermissionException {
    if (!isCertprofilePermitted(certprofile)) {
      throw new  InsuffientPermissionException("Certprofile " + certprofile + " is not permitted");
    }
  }

  @Override
  public void assertPermitted(int permission) throws InsuffientPermissionException {
    if (!isPermitted(permission)) {
      throw new InsuffientPermissionException("Permission "
          + PermissionConstants.getTextForCode(permission) + " is not permitted");
    }
  }

}
