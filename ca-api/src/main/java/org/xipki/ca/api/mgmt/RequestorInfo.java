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

import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.InsufficientPermissionException;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.CaHasUserEntry;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;

import java.util.Set;

/**
 * Requestor info interface.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface RequestorInfo {

  String NAME_BY_USER = "by-user";

  String NAME_BY_CA = "by-ca";

  /**
   * CA system as the requestor.
   *
   */

  class ByCaRequestorInfo implements RequestorInfo {

    private final NameId ident;

    public ByCaRequestorInfo(NameId ident) {
      this.ident = Args.notNull(ident, "ident");
    }

    @Override
    public NameId getIdent() {
      return ident;
    }

    @Override
    public boolean isRa() {
      return false;
    }

    @Override
    public boolean isCertprofilePermitted(String certprofile) {
      return true;
    }

    @Override
    public boolean isPermitted(int requiredPermission) {
      return true;
    }

    @Override
    public void assertPermitted(int requiredPermission)
        throws InsufficientPermissionException {
    }

  } // class ByCaRequestorInfo

  /**
   * CMP requestor info.
   *
   */
  class CmpRequestorInfo implements RequestorInfo {

    private final CaHasRequestorEntry caHasRequestor;

    private final CertWithDbId cert;

    private final char[] password;

    private final byte[] keyId;

    public CmpRequestorInfo(CaHasRequestorEntry caHasRequestor, CertWithDbId cert) {
      this.caHasRequestor = Args.notNull(caHasRequestor, "caHasRequestor");
      this.cert = Args.notNull(cert, "cert");
      this.password = null;
      this.keyId = null;
    }

    public CmpRequestorInfo(CaHasRequestorEntry caHasRequestor,
        char[] password, byte[] keyId) {
      this.caHasRequestor = Args.notNull(caHasRequestor, "caHasRequestor");
      this.cert = null;
      this.password = Args.notNull(password, "password");
      this.keyId = Args.notNull(keyId, "keyId");
    }

    public CaHasRequestorEntry getCaHasRequestor() {
      return caHasRequestor;
    }

    public CertWithDbId getCert() {
      return cert;
    }

    public char[] getPassword() {
      return password;
    }

    public byte[] getKeyId() {
      return keyId;
    }

    @Override
    public NameId getIdent() {
      return caHasRequestor.getRequestorIdent();
    }

    @Override
    public boolean isRa() {
      return caHasRequestor.isRa();
    }

    @Override
    public boolean isCertprofilePermitted(String certprofile) {
      return caHasRequestor.isCertprofilePermitted(certprofile);
    }

    @Override
    public boolean isPermitted(int permission) {
      return caHasRequestor.isPermitted(permission);
    }

    @Override
    public void assertPermitted(int permission)
        throws InsufficientPermissionException {
      if (!isPermitted(permission)) {
        throw new  InsufficientPermissionException("Permission "
            + PermissionConstants.getTextForCode(permission) + " is not permitted");
      }
    }

  } // method CmpRequestorInfo

  /**
   * Represent requestor that is authenticated via user/password.
   *
   */

  class ByUserRequestorInfo implements RequestorInfo {

    private final NameId ident;

    private final CaHasUserEntry caHasUser;

    public ByUserRequestorInfo(NameId ident, CaHasUserEntry caHasUser) {
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

    public CaHasUserEntry getCaHasUser() {
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
    public void assertPermitted(int permission)
        throws InsufficientPermissionException {
      if (!isPermitted(permission)) {
        throw new InsufficientPermissionException("Permission "
            + PermissionConstants.getTextForCode(permission) + " is not permitted");
      }
    }

  } // class ByUserRequestorInfo

  NameId getIdent();

  boolean isRa();

  boolean isCertprofilePermitted(String certprofile);

  boolean isPermitted(int requiredPermission);

  void assertPermitted(int requiredPermission)
      throws InsufficientPermissionException;

}
