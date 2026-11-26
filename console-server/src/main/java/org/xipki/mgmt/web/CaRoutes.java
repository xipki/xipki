// License Apache License 2.0

package org.xipki.mgmt.web;

import java.util.*;
import org.xipki.mgmt.web.audit.AuditTargetCapture;
import org.xipki.mgmt.web.controller.*;
import org.xipki.mgmt.web.core.Routes;
import org.xipki.mgmt.web.dto.*;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Action;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Certificate;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Prepare;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Reconcile;
import org.xipki.mgmt.web.security.*;
import org.xipki.mgmt.web.service.*;

/**
 * Explicit domain bindings; authorization and audit are enforced before dispatch.
 *
 * @author palos
 */
public final class CaRoutes {
  private CaRoutes() {}

  /** Registers every CA-domain handler against the matching fail-closed permission policy. */
  public static void register(
      Routes routes,
      CaManagementService service,
      CaConfigurationService configuration,
      QuickStartService quickStartService,
      AccessControl access,
      AccountService accounts,
      CaEnrollmentRepository repository,
      CaEnrollmentService enrollment,
      CertificateOwnership ownership,
      AuditTargetCapture audit) {
    var quickStart = new QuickStartController(quickStartService, access);
    routes.add("GET", "/api/quick-start", r -> quickStart.status());
    routes.add(
        "POST", "/api/quick-start", r -> quickStart.execute(r.body(QuickStartRequest.class)));

    var ca = new CaController(service, configuration, access, accounts, repository);
    routes.add("GET", "/api/ca", r -> ca.listCas());
    routes.add("GET", "/api/ca/{name}", r -> ca.getCa(r.path("name")));
    routes.add("POST", "/api/ca", r -> ca.addCa(r.body(ImportCaRequest.class)));
    routes.add("POST", "/api/ca/preflight", r -> ca.preflight(r.body(CaCertificateRequest.class)));
    routes.add("POST", "/api/ca/root", r -> ca.createRoot(r.body(CreateRootCaRequest.class)));
    routes.add("GET", "/api/ca/{name}/config", r -> ca.config(r.path("name")));
    routes.add(
        "PUT",
        "/api/ca/{name}/config",
        r -> ca.updateCa(r.path("name"), r.body(CaConfigurationRequest.class)));
    routes.add(
        "GET",
        "/api/ca/{name}/certificates",
        r -> ca.certificates(r.path("name"), r.param("format", "pem")));
    routes.add(
        "DELETE", "/api/ca/{name}", r -> ca.removeCa(r.path("name"), r.required("confirmName")));
    routes.add(
        "POST", "/api/ca/{name}/revoke", r -> ca.revokeCa(r.path("name"), r.body(Map.class)));
    routes.add("POST", "/api/ca/{name}/unrevoke", r -> ca.unrevokeCa(r.path("name")));
    routes.add("POST", "/api/ca/{name}/restart", r -> ca.restartCa(r.path("name")));
    routes.add("GET", "/api/ca/aliases", r -> ca.listAliases());
    routes.add("POST", "/api/ca/aliases", r -> ca.addAlias(r.body(Map.class)));
    routes.add("DELETE", "/api/ca/aliases/{alias}", r -> ca.removeAlias(r.path("alias")));
    routes.add("GET", "/api/ca/{name}/delete-impact", r -> ca.deleteImpact(r.path("name")));

    var options = new CaOptionsController(service, access);
    routes.add("GET", "/api/ca-options", r -> options.options(r.param("ca")));
    routes.add(
        "GET",
        "/api/ca/{name}/association-options",
        r -> options.associations(r.path("name"), r.required("kind")));
    routes.add("GET", "/api/ca/{name}/crypto-options", r -> options.crypto(r.path("name")));

    var operations = new CaEnrollmentController(enrollment, audit);
    routes.add("GET", "/api/ca-enrollments", r -> operations.list());
    routes.add("GET", "/api/ca-enrollments/options", r -> operations.options());
    routes.add(
        "POST", "/api/ca-enrollments", r -> operations.prepare(r.body(Prepare.class), r.req()));
    routes.add("GET", "/api/ca-enrollments/{id}", r -> operations.get(r.path("id")));
    routes.add("GET", "/api/ca-enrollments/{id}/csr", r -> operations.csr(r.path("id")));
    routes.add(
        "POST",
        "/api/ca-enrollments/{id}/issue",
        r -> operations.issue(r.path("id"), r.body(Action.class), r.req()));
    routes.add(
        "POST",
        "/api/ca-enrollments/{id}/certificate",
        r -> operations.certificate(r.path("id"), r.body(Certificate.class), r.req()));
    routes.add(
        "POST",
        "/api/ca-enrollments/{id}/register",
        r -> operations.register(r.path("id"), r.body(Action.class), r.req()));
    routes.add(
        "POST",
        "/api/ca-enrollments/{id}/reconcile",
        r -> operations.reconcile(r.path("id"), r.body(Reconcile.class), r.req()));
    routes.add(
        "POST",
        "/api/ca-enrollments/{id}/cancel",
        r -> operations.cancel(r.path("id"), r.body(Action.class), r.req()));

    var cert = new CertController(service, access, ownership);
    routes.add(
        "GET",
        "/api/cert",
        r ->
            cert.listCerts(
                r.resp(),
                r.required("ca"),
                r.param("subject"),
                r.param("validFrom"),
                r.param("validTo"),
                r.param("orderBy", "notBefore"),
                r.integer("limit", 20),
                r.bool("paged", false),
                r.param("cursor")));
    routes.add("GET", "/api/cert/{ca}/{serial}", r -> cert.getCert(r.path("ca"), r.path("serial")));
    routes.add(
        "POST",
        "/api/cert/enroll",
        r ->
            cert.enrollCert(
                r.req(),
                r.required("ca"),
                r.required("profile"),
                r.upload("csr"),
                r.param("notBefore"),
                r.param("notAfter")));
    routes.add(
        "POST",
        "/api/cert/enroll-cross",
        r ->
            cert.enrollCross(
                r.req(),
                r.required("ca"),
                r.required("profile"),
                r.upload("csr"),
                r.upload("targetCert"),
                r.param("notBefore"),
                r.param("notAfter")));
    routes.add(
        "POST",
        "/api/cert/enroll-key",
        r ->
            cert.enrollKeyCert(
                r.req(),
                r.resp(),
                r.required("ca"),
                r.required("profile"),
                r.required("subject"),
                r.param("notBefore"),
                r.param("notAfter")));
    routes.add(
        "POST",
        "/api/cert/enroll-key/download",
        r -> cert.downloadKeyCert(r.req(), r.body(KeyCertDownloadRequest.class)));
    routes.add(
        "POST",
        "/api/cert/{ca}/{serial}/revoke",
        r -> cert.revokeCert(r.path("ca"), r.path("serial"), r.body(Map.class)));
    routes.add(
        "POST",
        "/api/cert/{ca}/{serial}/unsuspend",
        r -> cert.unsuspendCert(r.path("ca"), r.path("serial")));
    routes.add(
        "DELETE", "/api/cert/{ca}/{serial}", r -> cert.removeCert(r.path("ca"), r.path("serial")));
    routes.add(
        "GET",
        "/api/cert/{ca}/{serial}/download",
        r -> cert.downloadCert(r.path("ca"), r.path("serial"), r.param("format", "pem")));

    var crl = new CrlController(service, access);
    routes.add("POST", "/api/crl/{ca}/generate", r -> crl.generateCrl(r.path("ca")));
    routes.add("GET", "/api/crl/{ca}/current", r -> crl.downloadCurrentCrl(r.path("ca")));
    routes.add(
        "GET", "/api/crl/{ca}/{number}", r -> crl.downloadCrl(r.path("ca"), r.path("number")));

    var profiles = new ProfileController(service, access);
    routes.add("GET", "/api/profile", r -> profiles.listProfiles());
    routes.add("GET", "/api/profile/{name}", r -> profiles.getProfile(r.path("name")));
    routes.add("POST", "/api/profile", r -> profiles.addProfile(r.body(NameTypeConfDto.class)));
    routes.add(
        "PUT",
        "/api/profile/{name}",
        r -> profiles.updateProfile(r.path("name"), r.body(NameTypeConfDto.class)));
    routes.add("DELETE", "/api/profile/{name}", r -> profiles.removeProfile(r.path("name")));
    routes.add(
        "GET",
        "/api/profile/ca/{ca}",
        r -> profiles.getProfilesForCa(r.path("ca"), r.param("operation")));
    routes.add(
        "GET",
        "/api/profile/ca/{ca}/associations",
        r -> profiles.getProfileAssociations(r.path("ca")));
    routes.add(
        "POST",
        "/api/profile/{name}/ca/{ca}",
        r ->
            profiles.addProfileToCa(
                r.path("name"),
                r.path("ca"),
                r.req().getContentLengthLong() == 0
                    ? null
                    : r.body(ProfileAssociationRequest.class)));
    routes.add(
        "DELETE",
        "/api/profile/{name}/ca/{ca}",
        r -> profiles.removeProfileFromCa(r.path("name"), r.path("ca")));

    var publishers = new PublisherController(service, access);
    routes.add("GET", "/api/publisher", r -> publishers.listPublishers());
    routes.add("GET", "/api/publisher/{name}", r -> publishers.getPublisher(r.path("name")));
    routes.add(
        "POST", "/api/publisher", r -> publishers.addPublisher(r.body(NameTypeConfDto.class)));
    routes.add(
        "PUT",
        "/api/publisher/{name}",
        r -> publishers.updatePublisher(r.path("name"), r.body(NameTypeConfDto.class)));
    routes.add("DELETE", "/api/publisher/{name}", r -> publishers.removePublisher(r.path("name")));
    routes.add("GET", "/api/publisher/ca/{ca}", r -> publishers.getPublishersForCa(r.path("ca")));
    routes.add(
        "POST",
        "/api/publisher/{name}/ca/{ca}",
        r -> publishers.addPublisherToCa(r.path("name"), r.path("ca")));
    routes.add(
        "DELETE",
        "/api/publisher/{name}/ca/{ca}",
        r -> publishers.removePublisherFromCa(r.path("name"), r.path("ca")));

    var requestors = new RequestorController(service, access);
    routes.add("GET", "/api/requestor", r -> requestors.listRequestors());
    routes.add("GET", "/api/requestor/{name}", r -> requestors.getRequestor(r.path("name")));
    routes.add(
        "POST", "/api/requestor", r -> requestors.addRequestor(r.body(NameTypeConfDto.class)));
    routes.add(
        "PUT",
        "/api/requestor/{name}",
        r -> requestors.updateRequestor(r.path("name"), r.body(NameTypeConfDto.class)));
    routes.add("DELETE", "/api/requestor/{name}", r -> requestors.removeRequestor(r.path("name")));
    routes.add("GET", "/api/requestor/ca/{ca}", r -> requestors.getRequestorsForCa(r.path("ca")));
    routes.add(
        "POST",
        "/api/requestor/{name}/ca/{ca}",
        r ->
            requestors.addRequestorToCa(
                r.path("name"), r.path("ca"), r.body(RequestorAssociationRequest.class)));
    routes.add(
        "PUT",
        "/api/requestor/{name}/ca/{ca}",
        r ->
            requestors.updateRequestorForCa(
                r.path("name"), r.path("ca"), r.body(RequestorAssociationRequest.class)));
    routes.add(
        "DELETE",
        "/api/requestor/{name}/ca/{ca}",
        r -> requestors.removeRequestorFromCa(r.path("name"), r.path("ca")));

    var signers = new SignerController(service);
    routes.add("GET", "/api/signer", r -> signers.listSigners());
    routes.add("GET", "/api/signer/{name}", r -> signers.getSigner(r.path("name")));
    routes.add("POST", "/api/signer", r -> signers.addSigner(r.body(NameTypeConfDto.class)));
    routes.add(
        "PUT",
        "/api/signer/{name}",
        r -> signers.updateSigner(r.path("name"), r.body(NameTypeConfDto.class)));
    routes.add("DELETE", "/api/signer/{name}", r -> signers.removeSigner(r.path("name")));

    var keypairs = new KeypairGenController(service);
    routes.add("GET", "/api/keypairgen", r -> keypairs.listKeypairGens());
    routes.add("GET", "/api/keypairgen/{name}", r -> keypairs.getKeypairGen(r.path("name")));
    routes.add(
        "POST", "/api/keypairgen", r -> keypairs.addKeypairGen(r.body(NameTypeConfDto.class)));
    routes.add(
        "PUT",
        "/api/keypairgen/{name}",
        r -> keypairs.updateKeypairGen(r.path("name"), r.body(NameTypeConfDto.class)));
    routes.add("DELETE", "/api/keypairgen/{name}", r -> keypairs.removeKeypairGen(r.path("name")));

    var schemas = new DbSchemaController(service);
    routes.add("GET", "/api/dbschema", r -> schemas.listDbSchemas());
    routes.add("POST", "/api/dbschema", r -> schemas.addDbSchema(r.body(Map.class)));
    routes.add(
        "PUT",
        "/api/dbschema/{name}",
        r -> schemas.updateDbSchema(r.path("name"), r.body(Map.class)));
    routes.add("DELETE", "/api/dbschema/{name}", r -> schemas.removeDbSchema(r.path("name")));

    var system = new SystemController(service, access);
    routes.add("GET", "/api/system/status", r -> system.getSystemStatus());
    routes.add("POST", "/api/system/restart", r -> system.restartSystem());
    routes.add("POST", "/api/system/unlock", r -> system.unlockSystem());
    routes.add("POST", "/api/system/notify-change", r -> system.notifyChange());
    routes.add(
        "POST", "/api/system/republish", r -> system.republish(r.body(RepublishRequest.class)));
    routes.add(
        "GET",
        "/api/system/export",
        r -> system.exportConf(names(r.req().getParameterValues("caNames"))));
    routes.add("POST", "/api/system/import", r -> system.importConf(r.upload("file"), r.resp()));
    routes.add(
        "GET",
        "/api/system/token-info",
        r ->
            system.getTokenInfo(
                r.param("module"),
                r.param("slot") == null ? null : r.integer("slot", 0),
                r.bool("verbose", false)));
    routes.add("GET", "/api/system/supported-types", r -> system.getSupportedTypes());
    var dashboard = new DashboardController(service, access);
    routes.add("GET", "/api/dashboard", r -> dashboard.dashboard());
  }

  private static List<String> names(String[] values) {
    if (values == null) {
      return null;
    }
    return Arrays.stream(values).flatMap(v -> Arrays.stream(v.split(","))).toList();
  }
}
