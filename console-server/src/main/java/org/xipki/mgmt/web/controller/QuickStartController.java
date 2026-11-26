// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import org.xipki.mgmt.web.ca.CaDomain.CaMgmtException;
import org.xipki.mgmt.web.core.AccessDeniedException;
import org.xipki.mgmt.web.dto.ApiResponse;
import org.xipki.mgmt.web.dto.QuickStartRequest;
import org.xipki.mgmt.web.dto.QuickStartStatus;
import org.xipki.mgmt.web.security.AccessControl;
import org.xipki.mgmt.web.security.AccountService;
import org.xipki.mgmt.web.service.QuickStartService;

/** Exposes the deployment-wide Quick Start workflow only to the built-in super administrator. */
public final class QuickStartController {
  private final QuickStartService service;
  private final AccessControl access;

  /** Creates the HTTP boundary around the Quick Start orchestrator. */
  public QuickStartController(QuickStartService service, AccessControl access) {
    this.service = service;
    this.access = access;
  }

  /** Returns eligibility and progress without changing CA state. */
  public ApiResponse<QuickStartStatus> status() throws CaMgmtException {
    requireSuperAdmin();
    return ApiResponse.ok(service.status());
  }

  /** Starts or resumes Quick Start after global permission and recent-auth checks. */
  public ApiResponse<QuickStartStatus> execute(QuickStartRequest request) throws CaMgmtException {
    requireSuperAdmin();
    access.requireGlobal("CA_CREATE_ROOT");
    return ApiResponse.ok(service.execute(request));
  }

  /** Prevents delegated platform roles from claiming deployment ownership through Quick Start. */
  private void requireSuperAdmin() {
    if (!AccountService.principal().isSuperAdmin()) {
      throw new AccessDeniedException("Super administrator required");
    }
  }
}
