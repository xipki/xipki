// License Apache License 2.0

package org.xipki.mgmt.web.service;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Proxy;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.xipki.codec.util.ConfPairs;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.core.ApiException;
import org.xipki.mgmt.web.core.Json;
import org.xipki.mgmt.web.dto.*;

/** Verifies the deployment-wide Quick Start orchestration interface. */
class QuickStartServiceTest {
  /** A clean deployment reaches a usable state, and an identical retry performs no writes. */
  @Test
  void emptyDeploymentBecomesImmediatelyUsableAndRetryIsIdempotent() throws Exception {
    var engine = new Engine();
    var management = new CaManagementService(engine.manager());
    var configuration = new Configuration(management, engine);
    var quickStart = new QuickStartService(management, configuration);
    var request = new QuickStartRequest();
    request.caName = "evaluation-ca";
    request.organization = "Example Organization";
    request.country = "CN";
    request.confirmed = true;

    QuickStartStatus result = quickStart.execute(request);

    assertEquals(QuickStartStatus.State.COMPLETED, result.state());
    assertEquals("evaluation-ca", result.caName());
    assertEquals(
        Set.of("quickstart-root", "quickstart-tls-server", "quickstart-tls-client"),
        engine.profiles.keySet());
    assertEquals("evaluation-ca", engine.aliases.get("quickstart"));
    assertEquals(
        Set.of("quickstart-tls-server", "quickstart-tls-client"),
        engine.associations.get("evaluation-ca"));
    assertTrue(engine.successful.contains("evaluation-ca"));
    assertEquals("RSA3072", configuration.created.key.algorithm);
    assertEquals("397d", configuration.created.config.maxValidity);
    assertEquals("CN=Evaluation CA,O=Example Organization,C=CN", configuration.created.subject);
    assertEquals(
        "10y",
        Json.read(engine.profiles.get("quickstart-root").getConf(), Map.class).get("validity"));
    assertEquals(
        "397d",
        Json.read(engine.profiles.get("quickstart-tls-server").getConf(), Map.class).get("validity"));
    assertEquals(
        Boolean.FALSE,
        extension(engine, "quickstart-tls-server", "AuthorityInfoAccess").get("required"));
    assertEquals(
        Boolean.FALSE,
        extension(engine, "quickstart-tls-client", "AuthorityInfoAccess").get("required"));

    quickStart.execute(request);

    assertEquals(3, engine.profileCreates);
    assertEquals(1, configuration.creates);
    assertEquals(2, engine.associationCreates);
    assertEquals(1, configuration.activations);
  }

  /** Conflicting user-owned resources must stop the workflow without being overwritten. */
  @Test
  void existingProfileWithDifferentContentFailsClosed() throws Exception {
    var engine = new Engine();
    engine.profiles.put(
        "quickstart-root",
        new CertprofileEntry(new NameId(null, "quickstart-root"), "xijson", "{\"version\":1}"));
    var quickStart =
        new QuickStartService(
            new CaManagementService(engine.manager()),
            new Configuration(new CaManagementService(engine.manager()), engine));

    ApiException error = assertThrows(ApiException.class, () -> quickStart.execute(request()));

    assertEquals(409, error.status());
    assertEquals(0, engine.profileCreates);
    assertTrue(engine.cas.isEmpty());
  }

  /** A failed remote step can be retried without duplicating resources created before the failure. */
  @Test
  void partialInitializationResumesFromObservedState() throws Exception {
    var engine = new Engine();
    engine.failAssociationOnce = true;
    var management = new CaManagementService(engine.manager());
    var configuration = new Configuration(management, engine);
    var quickStart = new QuickStartService(management, configuration);

    assertThrows(CaMgmtException.class, () -> quickStart.execute(request()));
    assertEquals(3, engine.profileCreates);
    assertEquals(1, configuration.creates);

    QuickStartStatus result = quickStart.execute(request());

    assertEquals(QuickStartStatus.State.COMPLETED, result.state());
    assertEquals(3, engine.profileCreates);
    assertEquals(1, configuration.creates);
    assertEquals(2, engine.associationCreates);
  }

  /** Quick Start registers the generated Gateway identity once with only lifecycle permissions. */
  @Test
  void gatewayRequestorIsProvisionedIdempotentlyWithLeastPrivilege() throws Exception {
    var engine = new Engine();
    var management = new CaManagementService(engine.manager());
    var quickStart =
        new QuickStartService(
            management,
            new Configuration(management, engine),
            GatewayRequestorProvisioner.fromDer(new byte[] {1, 2, 3, 4}));

    QuickStartStatus first = quickStart.execute(request());
    quickStart.execute(request());

    assertEquals(QuickStartStatus.State.COMPLETED, first.state());
    assertTrue(first.steps().stream().anyMatch(s -> s.code().equals("gateway") && s.complete()));
    assertEquals(1, engine.requestorCreates);
    assertEquals(1, engine.requestorAssociationCreates);
    RequestorEntry requestor = engine.requestors.get("gateway-ra");
    assertEquals("cert", requestor.getType());
    CaHasRequestorEntry association =
        engine.requestorAssociations.get("evaluation-ca").iterator().next();
    assertEquals(
        PermissionConstants.ENROLL_CERT
            | PermissionConstants.REVOKE_CERT
            | PermissionConstants.UNSUSPEND_CERT,
        association.getPermissions().getValue());
    assertEquals(
        Set.of("quickstart-tls-server", "quickstart-tls-client"), association.getProfiles());
  }

  /** A same-name operator requestor must stop Quick Start rather than being overwritten. */
  @Test
  void conflictingGatewayRequestorFailsClosed() throws Exception {
    var engine = new Engine();
    engine.requestors.put(
        "gateway-ra", new RequestorEntry(new NameId(9, "gateway-ra"), "cert", "different"));
    var management = new CaManagementService(engine.manager());
    var quickStart =
        new QuickStartService(
            management,
            new Configuration(management, engine),
            GatewayRequestorProvisioner.fromDer(new byte[] {1, 2, 3, 4}));

    ApiException error = assertThrows(ApiException.class, () -> quickStart.execute(request()));

    assertEquals(409, error.status());
    assertTrue(engine.cas.isEmpty());
    assertEquals("different", engine.requestors.get("gateway-ra").getConf());
  }

  /** Builds the confirmed default request shared by failure-path tests. */
  private QuickStartRequest request() {
    var request = new QuickStartRequest();
    request.caName = "evaluation-ca";
    request.organization = "Example Organization";
    request.country = "CN";
    request.confirmed = true;
    return request;
  }

  /** Returns one generated profile extension so Quick Start-specific safety changes are testable. */
  @SuppressWarnings("unchecked")
  private Map<String, Object> extension(Engine engine, String profile, String type)
      throws Exception {
    Map<String, Object> conf =
        Json.read(engine.profiles.get(profile).getConf(), Map.class);
    return extension(conf, type);
  }

  /** Finds one extension within an already parsed profile document. */
  @SuppressWarnings("unchecked")
  private Map<String, Object> extension(Map<String, Object> conf, String type) {
    return ((List<Map<String, Object>>) conf.get("extensions")).stream()
        .filter(extension -> type.equals(extension.get("type")))
        .findFirst()
        .orElseThrow();
  }

  private static final class Configuration extends CaConfigurationService {
    private final Engine engine;
    private CreateRootCaRequest created;
    private int creates;
    private int activations;

    /** Creates a state-recording configuration seam for the orchestration test. */
    Configuration(CaManagementService service, Engine engine) {
      super(service, new CaConfigurationMapper(), new CaKeyMaterialService());
      this.engine = engine;
    }

    /** Records root creation while preserving the production orchestration contract. */
    @Override
    public CaDto root(CreateRootCaRequest request) {
      created = request;
      creates++;
      var base = new BaseCaInfo("PKCS12", new Permissions(List.of("all")));
      base.setStatus(CaStatus.inactive);
      base.setExtraControl(new ConfPairs(request.config.extraControl));
      engine.cas.put(request.name, new CaEntry(base, new NameId(null, request.name), "generated"));
      var result = new CaDto();
      result.name = request.name;
      result.status = "inactive";
      return result;
    }

    /** Records final activation without generating test certificates. */
    @Override
    public void update(String name, CaConfigurationRequest request) {
      assertEquals("active", request.status);
      activations++;
      engine.cas.get(name).getBase().setStatus(CaStatus.active);
      engine.successful.add(name);
    }
  }

  private static final class Engine {
    final Map<String, CertprofileEntry> profiles = new LinkedHashMap<>();
    final Map<String, CaEntry> cas = new LinkedHashMap<>();
    final Map<String, String> aliases = new LinkedHashMap<>();
    final Map<String, Set<String>> associations = new LinkedHashMap<>();
    final Map<String, RequestorEntry> requestors = new LinkedHashMap<>();
    final Map<String, Set<CaHasRequestorEntry>> requestorAssociations = new LinkedHashMap<>();
    final Set<String> successful = new LinkedHashSet<>();
    int profileCreates;
    int associationCreates;
    int requestorCreates;
    int requestorAssociationCreates;
    boolean failAssociationOnce;

    /** Returns a proxy over the in-memory management state used by each test. */
    CaManager manager() {
      return (CaManager)
          Proxy.newProxyInstance(
              getClass().getClassLoader(), new Class<?>[] {CaManager.class}, this::invoke);
    }

    /** Emulates the small official management-client surface used by Quick Start. */
    private Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args)
        throws Throwable {
      return switch (method.getName()) {
        case "getCaNames" -> Set.copyOf(cas.keySet());
        case "getCa" -> required(cas, args[0], "CA");
        case "getSuccessfulCaNames" -> Set.copyOf(successful);
        case "getFailedCaNames" -> Set.of();
        case "getInactiveCaNames" -> {
          var names = new LinkedHashSet<>(cas.keySet());
          names.removeAll(successful);
          yield names;
        }
        case "getCertprofileNames" -> Set.copyOf(profiles.keySet());
        case "getCertprofile" -> required(profiles, args[0], "Certprofile");
        case "addCertprofile" -> {
          var entry = (CertprofileEntry) args[0];
          profiles.put(entry.getIdent().getName(), entry);
          profileCreates++;
          yield null;
        }
        case "getCaAliasNames" -> Set.copyOf(aliases.keySet());
        case "getCaNameForAlias" -> required(aliases, args[0], "CA alias");
        case "getAliasesForCa" ->
            aliases.entrySet().stream()
                .filter(e -> e.getValue().equals(args[0]))
                .map(Map.Entry::getKey)
                .collect(java.util.stream.Collectors.toSet());
        case "addCaAlias" -> {
          // The official endpoint resolves aliases only against its running-CA registry.
          if (!successful.contains(args[1])) {
            throw new CaMgmtException("unknown CA " + args[1]);
          }
          aliases.put((String) args[0], (String) args[1]);
          yield null;
        }
        case "getCertprofilesForCa" ->
            associations.getOrDefault(args[0], Set.of()).stream()
                .map(name -> new CaProfileEntry(name, Set.of()))
                .collect(java.util.stream.Collectors.toSet());
        case "addCertprofileToCa" -> {
          if (failAssociationOnce) {
            failAssociationOnce = false;
            throw new CaMgmtException("simulated transient failure");
          }
          var profile = CaProfileEntry.decode((String) args[0]).profileName();
          associations.computeIfAbsent((String) args[1], ignored -> new LinkedHashSet<>()).add(profile);
          associationCreates++;
          yield null;
        }
        case "getRequestorNames" -> Set.copyOf(requestors.keySet());
        case "getRequestor" -> required(requestors, args[0], "Requestor");
        case "addRequestor" -> {
          var entry = (RequestorEntry) args[0];
          requestors.put(entry.getIdent().getName(), entry);
          requestorCreates++;
          yield null;
        }
        case "getRequestorsForCa" ->
            Set.copyOf(requestorAssociations.getOrDefault(args[0], Set.of()));
        case "addRequestorToCa" -> {
          requestorAssociations
              .computeIfAbsent((String) args[1], ignored -> new LinkedHashSet<>())
              .add((CaHasRequestorEntry) args[0]);
          requestorAssociationCreates++;
          yield null;
        }
        case "restartCa" -> null;
        default -> throw new UnsupportedOperationException(method.getName());
      };
    }

    /** Mirrors the official management endpoint, which rejects missing named resources. */
    private <T> T required(Map<String, T> values, Object key, String type) throws CaMgmtException {
      T value = values.get(key);
      if (value == null) {
        throw new CaMgmtException("Unknown " + type + " " + key);
      }
      return value;
    }
  }
}
