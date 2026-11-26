// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import java.util.List;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public final class CaEnrollmentDtos {
  public static class Prepare extends StrictRequest {
    public String idempotencyKey;
    public String purpose;
    public String mode;
    public String name;
    public String parentCa;
    public String profile;
    public String subject;
    public String csr;
    public String notBefore;
    public String notAfter;
    public CaConfigurationRequest config;
    public CaKeyRequest key;
  }

  public static class Action extends StrictRequest {
    public Long version;
  }

  public static class Certificate extends Action {
    public String certificate;
    public List<String> certificateChain;
    public Boolean acceptUnknownRevocation;
  }

  public static class Reconcile extends Action {
    public Boolean confirmRegistrationNotCompleted;
  }

  private CaEnrollmentDtos() {}
}
