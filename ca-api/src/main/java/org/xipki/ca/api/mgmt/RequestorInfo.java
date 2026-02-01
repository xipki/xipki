// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.exception.InsufficientPermissionException;

/**
 * Requestor info interface.
 *
 * @author Lijun Liao (xipki)
 */

public interface RequestorInfo {

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
    public NameId ident() {
      return ident;
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
   * Cert requestor info.
   *
   */
  class CertRequestorInfo implements RequestorInfo {

    private final CaHasRequestorEntry caHasRequestor;

    private final CertWithDbId cert;

    public CertRequestorInfo(CaHasRequestorEntry caHasRequestor,
                             CertWithDbId cert) {
      this.caHasRequestor = Args.notNull(caHasRequestor, "caHasRequestor");
      this.cert = Args.notNull(cert, "cert");
    }

    public CaHasRequestorEntry caHasRequestor() {
      return caHasRequestor;
    }

    public CertWithDbId cert() {
      return cert;
    }

    @Override
    public NameId ident() {
      return caHasRequestor.requestorIdent();
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
            + PermissionConstants.getTextForCode(permission)
            + " is not permitted");
      }
    }

  } // method CmpRequestorInfo

  NameId ident();

  boolean isCertprofilePermitted(String certprofile);

  boolean isPermitted(int requiredPermission);

  void assertPermitted(int requiredPermission)
      throws InsufficientPermissionException;

}
