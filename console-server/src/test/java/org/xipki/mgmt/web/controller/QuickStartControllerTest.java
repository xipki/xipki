// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.xipki.mgmt.web.core.AccessDeniedException;
import org.xipki.mgmt.web.core.RequestContext;
import org.xipki.mgmt.web.dto.QuickStartRequest;
import org.xipki.mgmt.web.security.*;

/** Verifies the additional deployment-owner boundary around Quick Start. */
class QuickStartControllerTest {
  /** Clears thread-local identity after each authorization test. */
  @AfterEach
  void clearIdentity() {
    RequestContext.clear();
  }

  /** A delegated platform role cannot claim initial deployment ownership. */
  @Test
  void delegatedRootCreatorCannotUseQuickStart() {
    RequestContext.bind(null, principal("CA_ADMIN"));
    var controller = new QuickStartController(null, null);

    AccessDeniedException error = assertThrows(AccessDeniedException.class, controller::status);

    assertEquals(403, error.status());
  }

  /** Even the super administrator must recently authenticate before Quick Start writes. */
  @Test
  void superAdministratorWriteRequiresRecentAuthentication() {
    RequestContext.bind(null, principal("SUPER_ADMIN"));
    var controller = new QuickStartController(null, new AccessControl(null));

    AccessDeniedException error =
        assertThrows(AccessDeniedException.class, () -> controller.execute(new QuickStartRequest()));

    assertEquals(403, error.status());
    assertEquals("Reauthentication required", error.getMessage());
  }

  /** Creates a platform principal with only the permission needed to reach the controller. */
  private WebPrincipal principal(String roleName) {
    var role =
        new RoleDefinition(
            roleName,
            roleName,
            "",
            "PLATFORM",
            roleName.equals("SUPER_ADMIN"),
            true,
            false,
            1,
            Set.of("CA_CREATE_ROOT"));
    var binding =
        new RoleBinding(roleName, "PLATFORM", null, null, false, List.of(), role);
    return new WebPrincipal(1, "admin", "hash", true, null, 1, false, List.of(binding));
  }
}
