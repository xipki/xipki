// License Apache License 2.0

package org.xipki.mgmt.web.service;

import static org.xipki.mgmt.web.service.CaEnrollmentRepository.*;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;
import javax.security.auth.x500.X500Principal;
import org.xipki.codec.util.ConfPairs;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.Crypto;
import org.xipki.mgmt.web.ca.Crypto.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.core.Jdbc.DuplicateKeyException;
import org.xipki.mgmt.web.dto.*;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Certificate;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Prepare;
import org.xipki.mgmt.web.security.*;
import org.xipki.mgmt.web.service.CaCertificateValidationService.ValidationPurpose;
import org.xipki.mgmt.web.service.CaKeyMaterialService.Material;

/**
 * Durable, explicitly resumed CA enrollment; no automatic replay of remote writes.
 *
 * @author palos
 */
public class CaEnrollmentService {
  private final CaEnrollmentRepository repository;
  private final EnrollmentKeyStore keys;
  private final CaManagementService engine;
  private final AccessControl access;
  private final CaConfigurationService configuration;
  private final CaKeyMaterialService materials;
  private final CaCertificateValidationService certificates;
  private final List<String> caRdnOrder;

  public CaEnrollmentService(
      CaEnrollmentRepository repository,
      EnrollmentKeyStore keys,
      CaManagementService engine,
      AccessControl access,
      CaConfigurationService configuration,
      CaKeyMaterialService materials,
      CaCertificateValidationService certificates,
      List<String> caRdnOrder) {
    this.repository = repository;
    this.keys = keys;
    this.engine = engine;
    this.access = access;
    this.configuration = configuration;
    this.materials = materials;
    this.certificates = certificates;
    this.caRdnOrder = List.copyOf(caRdnOrder);
  }

  public static void requireState(Status actual, Status... allowed) {
    if (!Arrays.asList(allowed).contains(actual)) {
      throw conflict();
    }
  }

  private void authorize(Operation op, boolean mutation) throws CaMgmtException {
    if (op.ownerId() != AccountService.principal().id() || op.purpose().equals("REGISTER_CA")) {
      if (!access.has("CA_IMPORT")
          || !AccountService.principal().bindings().stream()
              .anyMatch(
                  b ->
                      b.scope().equals("PLATFORM")
                          && b.definition().active()
                          && b.definition().permissions().contains("CA_IMPORT"))) {
        throw new AccessDeniedException("Enrollment management is not permitted");
      }
      if (mutation) {
        access.requireGlobal("CA_IMPORT");
      }
    }
    if (op.data().parentCa != null) {
      // Recovery consumes an existing certificate; parent runtime/profile availability
      // is a precondition for new issuance, not a substitute for scoped authorization.
      var identity = access.require("CA_ISSUE_SUBCA", op.data().parentCa, op.data().profile);
      if (!identity.fingerprint().equals(op.data().parentFingerprint)) {
        throw new AccessDeniedException("Parent CA changed");
      }
    }
    if (mutation) {
      RecentAuthentication.require();
    }
  }

  public Operation get(String id) throws CaMgmtException {
    var op = repository.get(id);
    authorize(op, false);
    return op;
  }

  public List<Operation> list() throws CaMgmtException {
    boolean all = access.has("CA_IMPORT");
    // Do not disclose operations whose parent scope the caller has since lost.
    var result = new ArrayList<Operation>();
    for (var op : repository.list(AccountService.principal().id(), all)) {
      try {
        authorize(op, false);
        result.add(op);
      } catch (AccessDeniedException ignored) {
      }
    }
    return result;
  }

  private Operation action(String id, Long version) throws CaMgmtException {
    var op = repository.get(id);
    authorize(op, true);
    if (version == null || version != op.version()) {
      throw conflict();
    }
    return op;
  }

  public Operation prepare(Prepare r) throws Exception {
    if (r.idempotencyKey == null || !r.idempotencyKey.matches("[a-zA-Z0-9_.-]{8,128}")) {
      throw new IllegalArgumentException("Idempotency key required");
    }
    if (!Set.of("SIGN_ONLY", "REGISTER_CA").contains(Objects.toString(r.purpose, ""))
        || !Set.of("ONLINE", "EXTERNAL").contains(Objects.toString(r.mode, ""))) {
      throw new IllegalArgumentException("Invalid enrollment purpose or mode");
    }
    RecentAuthentication.require();
    if (r.purpose.equals("REGISTER_CA")) {
      access.requireGlobal("CA_IMPORT");
    }
    if (r.purpose.equals("SIGN_ONLY")
        && (!r.mode.equals("ONLINE")
            || r.csr == null
            || r.key != null
            || r.config != null
            || r.name != null)) {
      throw new IllegalArgumentException("Sign-only requires an external CSR and a local parent");
    }
    var d = new Data();
    d.mode = r.mode;
    d.stage = "PREPARE";
    if (r.mode.equals("ONLINE")) {
      var grant = access.requireSubCaIssue(r.parentCa, r.profile);
      d.parentCa = grant.ca().name();
      d.parentFingerprint = grant.ca().fingerprint();
      d.profile = grant.profile();
      d.profileHash = profileHash(d.profile);
      parent(d);
    } else if (r.parentCa != null || r.profile != null) {
      throw new IllegalArgumentException("External enrollment has no local issuing parent");
    }
    if (r.purpose.equals("REGISTER_CA")) {
      d.name = CaConfigurationMapper.name(r.name);
      if (engine.getCaManager().getCaNames().contains(d.name)) {
        throw conflict();
      }
      d.config = r.config;
      if (d.config != null && d.config.status != null && !d.config.status.equals("inactive")) {
        throw new IllegalArgumentException("New CA must be inactive");
      }
      new CaConfigurationMapper()
          .create(
              "PKCS12", d.config,
              null); // Reject secret/pass-through configuration before storing metadata.
    }
    d.notBefore = r.notBefore;
    d.notAfter = r.notAfter;
    CaConfigurationService.dates(
        CaConfigurationService.instant(r.notBefore), CaConfigurationService.instant(r.notAfter));
    String hash = AccessControl.fingerprint(Json.bytes(r));
    long owner = AccountService.principal().id();
    var existing = repository.idempotent(owner, r.idempotencyKey, hash);
    if (existing != null) {
      authorize(existing, false);
      return existing;
    }
    String id = UUID.randomUUID().toString();
    Material material = null;
    if (r.purpose.equals("REGISTER_CA")) {
      if (r.key == null || !"pkcs11".equals(r.key.mode)) {
        keys.requireAvailable();
      }
      material = materials.prepare(r.key, null, true);
      d.keyType = material.type();
      if (material.type().equals("PKCS11")) {
        d.module = r.key.module;
        d.slotIndex = r.key.slotIndex;
        d.keyId = r.key.keyId;
        d.keyLabel = r.key.keyLabel;
        d.signatureAlgorithm = r.key.signatureAlgorithm;
      }
    }
    if (r.csr != null) {
      d.csr = Base64.getEncoder().encodeToString(csr(r.csr).getEncoded());
    } else {
      if (material == null || !material.type().equals("PKCS12") || r.subject == null) {
        throw new IllegalArgumentException("CSR and external HSM key reference required");
      }
      var pairs = new ConfPairs(material.conf());
      var store = store(pairs);
      var password = pairs.value("password").toCharArray();
      try {
        var key = (PrivateKey) store.getKey("main", password);
        var request =
            Crypto.csr(
                Crypto.csr(
                    new X500Principal(r.subject),
                    store.getCertificate("main").getPublicKey(),
                    key,
                    pairs.value("algo")));
        d.csr = Base64.getEncoder().encodeToString(request.getEncoded());
      } finally {
        Arrays.fill(password, '\0');
      }
    }
    var request = csr(d.csr);
    if (d.profile != null) {
      CaEnrollmentSubjectOrder.requireMatch(
          engine.getCaManager(), d.profile, request.getSubject(), caRdnOrder);
      var allowed =
          new ProfileCapabilitiesService(engine.getCaManager()).describe(d.profile).keyAlgorithms();
      var spec = Crypto.keySpec(request.getSubjectPublicKeyInfo());
      if (!allowed.isEmpty() && (spec == null || !allowed.contains(spec))) {
        throw new IllegalArgumentException("CSR key algorithm is not allowed by the profile");
      }
    }
    d.csrFingerprint = AccessControl.fingerprint(request.getEncoded());
    d.subjectKeyFingerprint =
        AccessControl.fingerprint(request.getSubjectPublicKeyInfo().getEncoded());
    if (material != null && material.type().equals("PKCS12")) {
      var pairs = new ConfPairs(material.conf());
      if (!Arrays.equals(
          store(pairs).getCertificate("main").getPublicKey().getEncoded(),
          request.getSubjectPublicKeyInfo().getEncoded())) {
        throw new IllegalArgumentException("CSR does not match hosted key");
      }
    }
    if (material != null && material.type().equals("PKCS12")) {
      keys.put(id, material.conf());
    }
    try {
      return repository.create(
          id,
          owner,
          r.idempotencyKey,
          hash,
          r.purpose,
          r.mode.equals("ONLINE") ? Status.PREPARED : Status.AWAITING_CERTIFICATE,
          d);
    } catch (DuplicateKeyException ex) {
      // Concurrent duplicate preparation may leave an encrypted orphan; never overwrite another
      // operation's key.
      existing = repository.idempotent(owner, r.idempotencyKey, hash);
      if (existing != null) {
        return existing;
      }
      throw ex;
    }
  }

  private static KeyStore store(ConfPairs pairs) throws Exception {
    var store = KeyStore.getInstance("PKCS12");
    char[] password = pairs.value("password").toCharArray();
    try {
      store.load(
          new ByteArrayInputStream(
              Base64.getDecoder().decode(pairs.value("keystore").substring(7))),
          password);
    } finally {
      Arrays.fill(password, '\0');
    }
    return store;
  }

  private static Csr csr(String text) throws Exception {
    return Crypto.csr(CaKeyMaterialService.decode(text));
  }

  private String profileHash(String profile) throws CaMgmtException {
    var entry = engine.getCaManager().getCertprofile(profile);
    if (entry == null) {
      throw new IllegalArgumentException("Profile unavailable");
    }
    return AccessControl.fingerprint(
        (entry.getType() + "\n" + entry.getConf()).getBytes(StandardCharsets.UTF_8));
  }

  private CaEntry parent(Data d) throws CaMgmtException {
    var entry = configuration.required(d.parentCa);
    if (!d.parentFingerprint.equals(CaCertificateValidationService.fingerprint(entry.getCert()))
        || entry.getBase().getStatus() != CaStatus.active
        || entry.getBase().getRevocationInfo() != null
        || !engine.getCaManager().getSuccessfulCaNames().contains(d.parentCa)) {
      throw new IllegalArgumentException("Parent CA is unavailable or changed");
    }
    var check =
        certificates.validate(
            entry.getCert(),
            entry.getCertchain(),
            Optional.empty(),
            Instant.now(),
            ValidationPurpose.ACTIVATE);
    if (!check.valid()) {
      throw new IllegalArgumentException(check.diagnostic());
    }
    var capability = new ProfileCapabilitiesService(engine.getCaManager()).describe(d.profile);
    if (!capability.supportsSubCa()) {
      throw new IllegalArgumentException("Parent path length does not permit this SubCA profile");
    }
    for (int i = 0; i < check.chain().size(); i++) {
      long below =
          check.chain().subList(0, i).stream()
              .filter(c -> !c.getSubject().equals(c.getIssuer()))
              .count();
      if (below + 1 > check.chain().get(i).getBasicConstraints()) {
        throw new IllegalArgumentException(
            "Ancestor CA path length does not permit another intermediate CA");
      }
    }
    configuration.requireNotKnownRevoked(check.chain());
    return entry;
  }

  public Operation issueOnline(String id, Long version) throws Exception {
    try (var guard = ProfileOperationLock.issuance()) {
      return issueOnlineLocked(id, version);
    }
  }

  private Operation issueOnlineLocked(String id, Long version) throws Exception {
    var op = action(id, version);
    requireState(op.status(), Status.PREPARED);
    var d = op.data();
    if (!d.mode.equals("ONLINE")) {
      throw conflict();
    }
    access.requireSubCaIssue(d.parentCa, d.profile);
    var issuer = parent(d);
    if (!profileHash(d.profile).equals(d.profileHash)) {
      throw conflict();
    }
    var request = csr(d.csr);
    CaEnrollmentSubjectOrder.requireMatch(
        engine.getCaManager(), d.profile, request.getSubject(), caRdnOrder);
    if (op.purpose().equals("REGISTER_CA") && "PKCS12".equals(d.keyType)) {
      try {
        var hosted = store(new ConfPairs(material(op)));
        if (!Arrays.equals(
            hosted.getCertificate("main").getPublicKey().getEncoded(),
            request.getSubjectPublicKeyInfo().getEncoded())) {
          throw new IllegalStateException();
        }
      } catch (Exception unavailable) {
        throw new IllegalStateException(
            "Hosted enrollment key is unavailable or does not match CSR");
      }
    }
    d.stage = "ISSUE";
    d.diagnostic = null;
    X509Cert issued;
    Instant notBefore = CaConfigurationService.instant(d.notBefore),
        notAfter = CaConfigurationService.instant(d.notAfter);
    if (notBefore == null || notBefore.isBefore(issuer.getCert().getNotBefore())) {
      notBefore = Instant.now();
    }
    if (notAfter == null || notAfter.isAfter(issuer.getCert().getNotAfter())) {
      notAfter = issuer.getCert().getNotAfter();
    }
    if (!notBefore.isBefore(notAfter)) {
      throw new IllegalArgumentException("Requested validity is outside the parent CA validity");
    }
    op = repository.move(op, Status.ISSUING, d); // Persist before crossing the network.
    try {
      issued =
          engine
              .getCaManager()
              .generateCertificate(
                  d.parentCa, d.profile, request.getEncoded(), notBefore, notAfter);
    } catch (Exception ex) {
      d.diagnostic = "Issuance result unknown; reconcile with the parent CA before continuing";
      return repository.move(op, Status.RESULT_UNKNOWN, d);
    }
    try {
      var chain = new ArrayList<X509Cert>();
      chain.add(issuer.getCert());
      if (issuer.getCertchain() != null) {
        chain.addAll(issuer.getCertchain());
      }
      accept(d, issued, chain, Optional.of(issuer.getCert()));
      return repository.move(op, Status.CERTIFICATE_READY, d);
    } catch (Exception ex) {
      // A certificate exists even if validation fails. Preserve it; do not send the CSR again.
      d.certificate = Base64.getEncoder().encodeToString(issued.getEncoded());
      d.diagnostic = "Issued certificate requires reconciliation and chain validation";
      return repository.move(op, Status.RESULT_UNKNOWN, d);
    }
  }

  private void accept(
      Data d, X509Cert cert, List<X509Cert> chain, Optional<X509Cert> expectedParent)
      throws Exception {
    var request = csr(d.csr);
    if (!Arrays.equals(
            request.getSubjectPublicKeyInfo().getEncoded(),
            cert.getSubjectPublicKeyInfo().getEncoded())
        || !request.getSubject().equals(cert.getSubject())) {
      throw new IllegalArgumentException("Certificate does not match CSR");
    }
    var check =
        certificates.validate(cert, chain, expectedParent, Instant.now(), ValidationPurpose.IMPORT);
    if (!check.valid() || check.selfSigned()) {
      throw new IllegalArgumentException("A valid intermediate CA chain is required");
    }
    configuration.requireNotKnownRevoked(check.chain());
    d.certificate = Base64.getEncoder().encodeToString(cert.getEncoded());
    d.issuedSubject = cert.getSubject().toString();
    d.issuedIssuer = cert.getIssuer().toString();
    d.issuedNotBefore = cert.getNotBefore().toString();
    d.issuedNotAfter = cert.getNotAfter().toString();
    d.issuedPathLength = cert.getBasicConstraints();
    d.certificateChain =
        check.chain().subList(1, check.chain().size()).stream()
            .map(c -> Base64.getEncoder().encodeToString(c.getEncoded()))
            .toList();
    d.diagnostic = null;
  }

  public Operation receiveCertificate(String id, Certificate r) throws Exception {
    var op = action(id, r.version);
    requireState(op.status(), Status.AWAITING_CERTIFICATE, Status.RESULT_UNKNOWN);
    var d = op.data();
    if (!Boolean.TRUE.equals(r.acceptUnknownRevocation)) {
      throw new IllegalArgumentException(
          "Explicit acceptance of externally unverified revocation status is required");
    }
    var expected =
        d.parentCa == null
            ? Optional.<X509Cert>empty()
            : Optional.of(configuration.required(d.parentCa).getCert());
    accept(
        d,
        CaKeyMaterialService.certificate(r.certificate),
        CaKeyMaterialService.certificates(r.certificateChain),
        expected);
    d.acceptUnknownRevocation = true;
    d.stage = "CERTIFICATE";
    return repository.move(op, Status.CERTIFICATE_READY, d);
  }

  public Operation register(String id, Long version) throws Exception {
    var op = action(id, version);
    if (!op.purpose().equals("REGISTER_CA")) {
      throw new AccessDeniedException("Sign-only operations cannot register a CA");
    }
    requireState(op.status(), Status.CERTIFICATE_READY, Status.FAILED);
    var d = op.data();
    if (d.certificate == null) {
      throw conflict();
    }
    var cert = CaKeyMaterialService.certificate(d.certificate);
    var chain = CaKeyMaterialService.certificates(d.certificateChain);
    var check =
        certificates.validate(
            cert, chain, Optional.empty(), Instant.now(), ValidationPurpose.IMPORT);
    if (!check.valid()) {
      throw new IllegalArgumentException(check.diagnostic());
    }
    configuration.requireNotKnownRevoked(check.chain());
    var material = material(op);
    if ("PKCS12".equals(d.keyType)) {
      material = materials.complete(material, cert, chain).conf();
    }
    var entry =
        new CaEntry(
            new CaConfigurationMapper().create(d.keyType, d.config, null),
            new NameId(null, d.name),
            material);
    entry.setCert(cert);
    entry.setCertchain(chain);
    if (engine.getCaManager().getCaNames().contains(d.name)) {
      throw conflict();
    }
    d.stage = "REGISTER";
    d.diagnostic = null;
    op = repository.move(op, Status.REGISTERING, d);
    try {
      engine.getCaManager().addCa(entry);
    } catch (Exception ex) {
      d.diagnostic = "Registration result unknown; reconcile before retrying registration";
      return repository.move(op, Status.RESULT_UNKNOWN, d);
    }
    return confirmRegistration(op);
  }

  private Operation confirmRegistration(Operation op) throws Exception {
    var d = op.data();
    var current = configuration.required(d.name);
    if (!Objects.equals(
            CaCertificateValidationService.fingerprint(current.getCert()),
            CaCertificateValidationService.fingerprint(
                CaKeyMaterialService.certificate(d.certificate)))
        || !Objects.equals(current.getBase().getSignerType(), d.keyType)) {
      throw conflict();
    }
    if ("PKCS11".equals(d.keyType)) {
      var expected = new ConfPairs(material(op));
      var actual = new ConfPairs(current.getSignerConf());
      for (String field : List.of("module", "slot", "key-id", "key-label")) {
        if (!Objects.equals(expected.value(field), actual.value(field))) {
          throw conflict();
        }
      }
    }
    d.diagnostic = null;
    var registered = repository.move(op, Status.REGISTERED, d);
    if ("PKCS12".equals(d.keyType) && !keys.remove(op.operationId())) {
      d.diagnostic = "CA registered; encrypted temporary key cleanup is pending";
      registered = repository.move(registered, Status.REGISTERED, d);
    }
    return registered;
  }

  public Operation reconcile(String id, Long version, boolean confirmRegistrationNotCompleted)
      throws Exception {
    var op = action(id, version);
    requireState(op.status(), Status.RESULT_UNKNOWN, Status.ISSUING, Status.REGISTERING);
    var d = op.data();
    if (d.stage.equals("REGISTER")) {
      if (engine.getCaManager().getCaNames().contains(d.name)) {
        var current = configuration.required(d.name);
        if (!CaCertificateValidationService.fingerprint(current.getCert())
            .equals(
                CaCertificateValidationService.fingerprint(
                    CaKeyMaterialService.certificate(d.certificate)))) {
          throw conflict();
        }
        return confirmRegistration(op);
      }
      if (confirmRegistrationNotCompleted && op.status() == Status.RESULT_UNKNOWN) {
        d.diagnostic =
            "Registration confirmed incomplete; retry uses the existing certificate and key";
        return repository.move(op, Status.FAILED, d);
      }
      // A read does not prove a timed-out write cannot still complete. Never enable a retry
      // automatically.
      d.diagnostic =
          "CA not found yet; verify the engine completed the request before retrying registration";
    } else {
      d.diagnostic =
          "Upload the certificate located in the parent CA issuance records; do not resubmit this"
              + " CSR";
    }
    return repository.move(op, Status.RESULT_UNKNOWN, d);
  }

  public Operation cancel(String id, Long version) throws Exception {
    var op = action(id, version);
    requireState(op.status(), Status.PREPARED, Status.AWAITING_CERTIFICATE, Status.FAILED);
    if (op.data().certificate != null) {
      throw conflict();
    }
    op.data().diagnostic = "Cancelled before issuance";
    var cancelled = repository.move(op, Status.CANCELLED, op.data());
    if ("PKCS12".equals(op.data().keyType) && !keys.remove(op.operationId())) {
      op.data().diagnostic = "Cancelled; encrypted temporary key cleanup is pending";
      cancelled = repository.move(cancelled, Status.CANCELLED, op.data());
    }
    return cancelled;
  }

  private String material(Operation op) {
    if (!"PKCS11".equals(op.data().keyType)) {
      return keys.get(op.operationId());
    }
    var d = op.data();
    var key = new CaKeyRequest();
    key.mode = "pkcs11";
    key.module = d.module;
    key.slotIndex = d.slotIndex;
    key.keyId = d.keyId;
    key.keyLabel = d.keyLabel;
    key.signatureAlgorithm = d.signatureAlgorithm;
    return materials.prepare(key, null, false).conf();
  }

  public List<Map<String, Object>> options() throws CaMgmtException {
    var result = new ArrayList<Map<String, Object>>();
    if (!access.has("CA_ISSUE_SUBCA")) {
      return result;
    }
    for (String name : engine.getCaManager().getCaNames()) {
      var identity = access.identity(name);
      var profiles = new ArrayList<Map<String, Object>>();
      for (var binding : engine.getCaManager().getCertprofilesForCa(name)) {
        var p = binding.getProfileName();
        var capability = new ProfileCapabilitiesService(engine.getCaManager()).describe(p);
        if (access.allows("CA_ISSUE_SUBCA", identity, p) && capability.supportsSubCa()) {
          var candidate = new Data();
          candidate.parentCa = name;
          candidate.parentFingerprint = identity.fingerprint();
          candidate.profile = p;
          try {
            parent(candidate);
          } catch (IllegalArgumentException unavailable) {
            continue;
          }
          var item = new LinkedHashMap<String, Object>();
          item.put("name", p);
          item.put("capabilities", capability);
          profiles.add(item);
        }
      }
      if (!profiles.isEmpty()) {
        result.add(
            Map.of("name", name, "fingerprint", identity.fingerprint(), "profiles", profiles));
      }
    }
    return result;
  }
}
