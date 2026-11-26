// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.xipki.mgmt.web.audit.AuditFilter;
import org.xipki.mgmt.web.audit.AuditTargetCapture;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.*;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Action;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Certificate;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Prepare;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Reconcile;
import org.xipki.mgmt.web.service.CaCertificateValidationService;
import org.xipki.mgmt.web.service.CaEnrollmentRepository.Operation;
import org.xipki.mgmt.web.service.CaEnrollmentService;
import org.xipki.mgmt.web.service.CaKeyMaterialService;

/**
 * @author palos
 */
public class CaEnrollmentController {
  private final CaEnrollmentService service;
  private final AuditTargetCapture audit;

  public CaEnrollmentController(CaEnrollmentService service, AuditTargetCapture audit) {
    this.service = service;
    this.audit = audit;
  }

  public ApiResponse<List<Operation>> list() throws Exception {
    return ApiResponse.ok(service.list());
  }

  public ApiResponse<List<Map<String, Object>>> options() throws Exception {
    return ApiResponse.ok(service.options());
  }

  public ApiResponse<Operation> prepare(Prepare body, HttpServletRequest request) throws Exception {
    AuditTargetCapture.identify(request, "name", body.name);
    AuditTargetCapture.identify(request, "ca", body.parentCa);
    AuditTargetCapture.identify(request, "profile", body.profile);
    var op = service.prepare(body);
    AuditTargetCapture.identify(request, "operation", op.operationId());
    return ApiResponse.ok(op);
  }

  public ApiResponse<Operation> get(String id) throws Exception {
    return ApiResponse.ok(service.get(id));
  }

  public Reply<byte[]> csr(String id) throws Exception {
    return Reply.ok()
        .contentType("application/pkcs10")
        .header("Content-Disposition", "attachment; filename=ca-request.csr")
        .header("Cache-Control", "no-store")
        .body(Base64.getDecoder().decode(service.get(id).data().csr));
  }

  public ApiResponse<Operation> issue(String id, Action body, HttpServletRequest request)
      throws Exception {
    intent(id, request);
    return outcome(service.issueOnline(id, body.version), request);
  }

  public ApiResponse<Operation> certificate(String id, Certificate body, HttpServletRequest request)
      throws Exception {
    intent(id, request);
    return outcome(service.receiveCertificate(id, body), request);
  }

  public ApiResponse<Operation> register(String id, Action body, HttpServletRequest request)
      throws Exception {
    intent(id, request);
    return outcome(service.register(id, body.version), request);
  }

  public ApiResponse<Operation> reconcile(String id, Reconcile body, HttpServletRequest request)
      throws Exception {
    intent(id, request);
    return outcome(
        service.reconcile(
            id, body.version, Boolean.TRUE.equals(body.confirmRegistrationNotCompleted)),
        request);
  }

  public ApiResponse<Operation> cancel(String id, Action body, HttpServletRequest request)
      throws Exception {
    intent(id, request);
    return outcome(service.cancel(id, body.version), request);
  }

  private void intent(String id, HttpServletRequest request) throws Exception {
    var op = service.get(id);
    AuditTargetCapture.identify(request, "parentFingerprint", op.data().parentFingerprint);
    if (op.data().certificate != null) {
      AuditTargetCapture.identify(
          request,
          "certificateFingerprint",
          CaCertificateValidationService.fingerprint(
              CaKeyMaterialService.certificate(op.data().certificate)));
    }
    audit.captureEnrollment(
        request, id, op.purpose(), op.data().parentCa, op.data().profile, op.data().name);
  }

  private ApiResponse<Operation> outcome(Operation op, HttpServletRequest request) {
    AuditTargetCapture.identify(request, "parentFingerprint", op.data().parentFingerprint);
    if (op.data().certificate != null) {
      try {
        AuditTargetCapture.identify(
            request,
            "certificateFingerprint",
            CaCertificateValidationService.fingerprint(
                CaKeyMaterialService.certificate(op.data().certificate)));
      } catch (Exception ignored) {
        /* Public damaged material remains available for reconciliation. */
      }
    }
    if (Set.of("RESULT_UNKNOWN", "FAILED").contains(op.status().name())) {
      request.setAttribute(AuditFilter.BUSINESS_FAILURE, "ENROLLMENT_" + op.status().name());
    }
    return ApiResponse.ok(op);
  }
}
