// License Apache License 2.0

package org.xipki.mgmt.web.service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.naming.ldap.Rdn;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.*;
import org.xipki.mgmt.web.dto.QuickStartStatus.State;
import org.xipki.mgmt.web.dto.QuickStartStatus.Step;

/**
 * Owns the complete Quick Start workflow behind a small idempotent interface. Progress is derived
 * from marked XiPKI resources so an ambiguous remote result can be reconciled without shadow state.
 */
public class QuickStartService {
  static final String ALIAS = "quickstart";
  static final String MARKER_KEY = "xipki.quickstart";
  static final String ROOT_PROFILE = "quickstart-root";
  static final String SERVER_PROFILE = "quickstart-tls-server";
  static final String CLIENT_PROFILE = "quickstart-tls-client";

  private record Profile(String name, String conf) {}

  private final CaManagementService management;
  private final CaConfigurationService configuration;
  private final GatewayRequestorProvisioner gateway;
  private final List<Profile> profiles;

  /** Creates the orchestrator around the authenticated official management adapter. */
  public QuickStartService(
      CaManagementService management, CaConfigurationService configuration) {
    this(management, configuration, GatewayRequestorProvisioner.disabled());
  }

  /** Creates the production orchestrator from deployment-owned Console settings. */
  public QuickStartService(
      CaManagementService management, CaConfigurationService configuration, Config config) {
    this(management, configuration, GatewayRequestorProvisioner.from(config));
  }

  /** Creates the orchestrator with optional deployment-owned Gateway authorization. */
  QuickStartService(
      CaManagementService management,
      CaConfigurationService configuration,
      GatewayRequestorProvisioner gateway) {
    this.management = Objects.requireNonNull(management);
    this.configuration = Objects.requireNonNull(configuration);
    this.gateway = Objects.requireNonNull(gateway);
    profiles =
        List.of(
            profile(ROOT_PROFILE, "quick-start/certprofile-rootca.json", null),
            profile(SERVER_PROFILE, "quick-start/certprofile-tls.json", "397d"),
            profile(CLIENT_PROFILE, "quick-start/certprofile-tls-c.json", "397d"));
  }

  /** Returns current eligibility and progress without mutating XiPKI. */
  public QuickStartStatus status() throws CaMgmtException {
    CaManager manager = management.getCaManager();
    Set<String> caNames = manager.getCaNames();
    Set<String> profileNames = manager.getCertprofileNames();
    String quickCa = markedCa(manager, caNames);
    List<Step> steps = steps(manager, quickCa, profileNames);
    boolean profileConflict = false;
    for (Profile profile : profiles) {
      CertprofileEntry existing =
          contains(profileNames, profile.name()) ? manager.getCertprofile(profile.name()) : null;
      if (existing != null && !matches(existing, profile)) {
        profileConflict = true;
        break;
      }
    }
    if (profileConflict) {
      return status(State.CONFLICT, false, quickCa, steps, "Quick Start resource conflict");
    }
    if (gateway.state(manager, quickCa) == GatewayRequestorProvisioner.State.CONFLICT) {
      return status(State.CONFLICT, false, quickCa, steps, "Gateway RA requestor conflict");
    }
    if (quickCa == null && !caNames.isEmpty()) {
      return status(
          State.UNAVAILABLE,
          false,
          null,
          steps,
          "Quick Start is available only before a Business CA is configured");
    }
    if (quickCa == null) {
      boolean started = steps.stream().anyMatch(Step::complete);
      return status(started ? State.IN_PROGRESS : State.AVAILABLE, true, null, steps, null);
    }
    boolean complete = steps.stream().allMatch(Step::complete);
    return status(
        complete ? State.COMPLETED : State.IN_PROGRESS, !complete, quickCa, steps, null);
  }

  /**
   * Creates or resumes the safe Business CA workflow. Every remote mutation is preceded by an
   * ownership/state check; existing non-Quick-Start resources are never overwritten or deleted.
   */
  public QuickStartStatus execute(QuickStartRequest request) throws CaMgmtException {
    Validated input = validate(request);
    try (var ignored = ProfileOperationLock.mutation()) {
      QuickStartStatus before = status();
      if (before.state() == State.CONFLICT || before.state() == State.UNAVAILABLE) {
        throw new ApiException(409, before.message());
      }
      if (before.caName() != null && !before.caName().equals(input.caName())) {
        throw new ApiException(409, "Quick Start is already bound to another CA");
      }
      CaManager manager = management.getCaManager();
      Set<String> aliasNames = manager.getCaAliasNames();
      String aliasTarget =
          contains(aliasNames, ALIAS) ? manager.getCaNameForAlias(ALIAS) : null;
      if (aliasTarget != null && !aliasTarget.equals(input.caName())) {
        throw new ApiException(409, "Quick Start alias belongs to another CA");
      }
      Set<String> profileNames = new HashSet<>(manager.getCertprofileNames());
      for (Profile profile : profiles) {
        ensureProfile(manager, profileNames, profile);
      }
      CaEntry ca =
          contains(manager.getCaNames(), input.caName()) ? manager.getCa(input.caName()) : null;
      if (ca == null) {
        configuration.root(rootRequest(input));
        ca = manager.getCa(input.caName());
      }
      requireOwned(ca);
      // XiPKI resolves aliases against its running-CA registry. Activate the newly created CA
      // before alias creation; otherwise the official API reports the persisted inactive CA as
      // unknown. Associations remain after this boundary so a failed alias is visibly resumable.
      if (ca.getBase().getStatus() != CaStatus.active) {
        var activation = new CaConfigurationRequest();
        activation.status = "active";
        activation.acceptUnknownRevocation = true;
        configuration.update(input.caName(), activation);
      }
      if (!manager.getSuccessfulCaNames().contains(input.caName())) {
        manager.restartCa(input.caName());
      }
      if (aliasTarget == null) {
        manager.addCaAlias(ALIAS, input.caName());
      }
      ensureAssociation(manager, input.caName(), SERVER_PROFILE);
      ensureAssociation(manager, input.caName(), CLIENT_PROFILE);
      gateway.ensure(manager, input.caName());
      return status();
    }
  }

  /** Creates an immutable status response from one observed management snapshot. */
  private QuickStartStatus status(
      State state, boolean available, String caName, List<Step> steps, String message) {
    return new QuickStartStatus(state, available, caName, List.copyOf(steps), message);
  }

  /** Builds stable, server-observed milestones instead of relying on browser or database flags. */
  private List<Step> steps(CaManager manager, String caName, Set<String> profileNames)
      throws CaMgmtException {
    boolean profileReady = true;
    for (Profile profile : profiles) {
      if (!contains(profileNames, profile.name())
          || !matches(manager.getCertprofile(profile.name()), profile)) {
        profileReady = false;
        break;
      }
    }
    boolean caReady = caName != null;
    Set<String> associated = new HashSet<>();
    if (caReady) {
      for (CaProfileEntry entry : manager.getCertprofilesForCa(caName)) {
        associated.add(entry.getProfileName());
      }
    }
    boolean associationsReady =
        associated.contains(SERVER_PROFILE) && associated.contains(CLIENT_PROFILE);
    boolean active =
        caReady
            && manager.getCa(caName).getBase().getStatus() == CaStatus.active
            && manager.getSuccessfulCaNames().contains(caName);
    var result = new ArrayList<Step>();
    result.add(new Step("profiles", profileReady));
    result.add(new Step("ca", caReady));
    result.add(new Step("associations", associationsReady));
    result.add(new Step("activation", active));
    GatewayRequestorProvisioner.State gatewayState = gateway.state(manager, caName);
    if (gatewayState != GatewayRequestorProvisioner.State.DISABLED) {
      result.add(new Step("gateway", gatewayState == GatewayRequestorProvisioner.State.READY));
    }
    return List.copyOf(result);
  }

  /** Locates the one CA explicitly marked as owned by this workflow. */
  private String markedCa(CaManager manager, Set<String> caNames) throws CaMgmtException {
    for (String name : caNames) {
      CaEntry entry = manager.getCa(name);
      if (owned(entry)) {
        return name;
      }
    }
    return null;
  }

  /** Compares names defensively because XiPKI resource identifiers are case-insensitive. */
  private boolean contains(Set<String> names, String expected) {
    return names.stream().anyMatch(name -> name.equalsIgnoreCase(expected));
  }

  /** Compares profile semantics so harmless JSON formatting differences do not create conflicts. */
  private boolean matches(CertprofileEntry entry, Profile profile) {
    return matches(entry, profile.conf());
  }

  /** Compares one profile document semantically so JSON formatting differences are harmless. */
  private boolean matches(CertprofileEntry entry, String expectedConf) {
    if (entry == null || !"xijson".equalsIgnoreCase(entry.getType())) {
      return false;
    }
    try {
      return Json.read(entry.getConf(), Object.class).equals(Json.read(expectedConf, Object.class));
    } catch (Exception ex) {
      return false;
    }
  }

  /** Creates a missing owned profile or rejects a conflicting user-managed profile. */
  private void ensureProfile(CaManager manager, Set<String> profileNames, Profile profile)
      throws CaMgmtException {
    if (!contains(profileNames, profile.name())) {
      manager.addCertprofile(
          new CertprofileEntry(new NameId(null, profile.name()), "xijson", profile.conf()));
      profileNames.add(profile.name());
      return;
    }
    CertprofileEntry existing = manager.getCertprofile(profile.name());
    if (matches(existing, profile)) {
      return;
    }
    throw new ApiException(409, "Quick Start profile already exists with different content");
  }

  /** Adds one missing profile association without duplicating existing state. */
  private void ensureAssociation(CaManager manager, String caName, String profile)
      throws CaMgmtException {
    boolean present =
        manager.getCertprofilesForCa(caName).stream()
            .anyMatch(entry -> entry.getProfileName().equalsIgnoreCase(profile));
    if (!present) {
      manager.addCertprofileToCa(profile, caName);
    }
  }

  /** Rejects an existing CA unless it carries the non-user-configurable ownership marker. */
  private void requireOwned(CaEntry entry) {
    if (!owned(entry)) {
      throw new ApiException(409, "CA name already exists outside Quick Start");
    }
  }

  /** Tests whether a CA was created by Quick Start and is therefore safe to resume. */
  private boolean owned(CaEntry entry) {
    return entry != null
        && entry.getBase() != null
        && entry.getBase().getExtraControl() != null
        && "true".equalsIgnoreCase(entry.getBase().getExtraControl().value(MARKER_KEY));
  }

  /** Produces the fixed safe root-CA request while leaving only identity fields user-selectable. */
  private CreateRootCaRequest rootRequest(Validated input) {
    var request = new CreateRootCaRequest();
    request.name = input.caName();
    request.subject = input.subject();
    request.profile = ROOT_PROFILE;
    request.nextCrlNo = 1L;
    request.key = new CaKeyRequest();
    request.key.mode = "generate";
    request.key.algorithm = "RSA3072";
    request.config = new CaConfigurationRequest();
    request.config.status = "inactive";
    request.config.maxValidity = "397d";
    request.config.permissions = List.of("all");
    request.config.saveCert = true;
    request.config.saveKeypair = false;
    request.config.serialNoLen = 20;
    request.config.extraControl = MARKER_KEY + "=true";
    return request;
  }

  private record Validated(String caName, String subject) {}

  /** Validates confirmation and converts the limited identity input into a safe X.500 subject. */
  private Validated validate(QuickStartRequest request) {
    if (request == null || !Boolean.TRUE.equals(request.confirmed)) {
      throw new IllegalArgumentException("Quick Start confirmation is required");
    }
    String name = CaConfigurationMapper.name(request.caName);
    String organization = text(request.organization, "Organization", 128);
    String country = request.country == null ? "" : request.country.trim().toUpperCase(Locale.ROOT);
    if (!country.isEmpty() && !country.matches("[A-Z]{2}")) {
      throw new IllegalArgumentException("Country must be a two-letter code");
    }
    String display = displayName(name);
    String subject = "CN=" + Rdn.escapeValue(display) + ",O=" + Rdn.escapeValue(organization);
    if (!country.isEmpty()) {
      subject += ",C=" + country;
    }
    return new Validated(name, subject);
  }

  /** Validates required human text without permitting controls or oversized values. */
  private String text(String value, String label, int max) {
    String result = value == null ? "" : value.trim();
    if (result.isEmpty()
        || result.codePointCount(0, result.length()) > max
        || result.codePoints().anyMatch(Character::isISOControl)) {
      throw new IllegalArgumentException(label + " is invalid");
    }
    return result;
  }

  /** Converts a resource identifier into a readable common name while preserving the CA acronym. */
  private String displayName(String name) {
    var words = new ArrayList<String>();
    for (String word : name.split("[-_.]+")) {
      words.add(
          word.equalsIgnoreCase("ca")
              ? "CA"
              : Character.toUpperCase(word.charAt(0)) + word.substring(1));
    }
    return String.join(" ", words);
  }

  /** Loads a trusted packaged profile and applies the agreed end-entity validity limit. */
  @SuppressWarnings("unchecked")
  private Profile profile(String name, String resource, String validity) {
    try (InputStream in = getClass().getClassLoader().getResourceAsStream(resource)) {
      if (in == null) {
        throw new IllegalStateException("Missing Quick Start profile: " + resource);
      }
      String source = new String(in.readAllBytes(), StandardCharsets.UTF_8);
      Map<String, Object> values = Json.read(source, Map.class);
      if (validity != null) {
        values.put("validity", validity);
        allowMissingAuthorityInfoAccess(values);
      }
      return new Profile(name, Json.write(values));
    } catch (Exception ex) {
      throw new IllegalStateException("Invalid Quick Start profile: " + resource, ex);
    }
  }

  /**
   * Lets an out-of-box CA issue before an operator configures its public CA-certificate and OCSP
   * URLs. XiPKI will still add AIA automatically once either URL is present.
   */
  @SuppressWarnings("unchecked")
  private void allowMissingAuthorityInfoAccess(Map<String, Object> profile) {
    Object configured = profile.get("extensions");
    if (!(configured instanceof List<?> extensions)) {
      throw new IllegalStateException("Quick Start profile has no extensions");
    }
    for (Object configuredExtension : extensions) {
      if (configuredExtension instanceof Map<?, ?> extension
          && "AuthorityInfoAccess".equals(extension.get("type"))) {
        ((Map<String, Object>) extension).put("required", false);
        return;
      }
    }
    throw new IllegalStateException("Quick Start TLS profile has no AuthorityInfoAccess extension");
  }
}
