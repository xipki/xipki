// License Apache License 2.0

package org.xipki.mgmt.web.service;

import java.util.LinkedHashSet;
import java.util.Set;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.service.ProfileCapabilities.CertLevel;

/**
 * Resolves capabilities from the actual XiPKI profile entry, never from its name.
 *
 * @author palos
 */
public class ProfileCapabilitiesService {
  private final CaManager manager;

  public ProfileCapabilitiesService(CaManager manager) {
    this.manager = manager;
  }

  public ProfileCapabilities describe(String profileName) {
    if (profileName == null || profileName.isBlank()) {
      return unknown("Profile name is required");
    }
    try {
      CertprofileEntry entry = manager.getCertprofile(profileName);
      if (entry == null || entry.isFaulty()) {
        return unknown("Unknown or faulty certificate profile");
      }
      if (!"xijson".equalsIgnoreCase(entry.getType())) {
        return unknown("Profile type does not expose a supported certificate level");
      }
      JsonMap root = JsonParser.parseMap(entry.getConf(), false);
      String rawLevel = root.getString("certLevel");
      if (rawLevel == null) {
        rawLevel = "";
      }
      CertLevel level =
          switch (rawLevel) {
            case "RootCA" -> CertLevel.ROOT_CA;
            case "SubCA" -> CertLevel.SUB_CA;
            case "EndEntity" -> CertLevel.END_ENTITY;
            case "CROSS", "Cross" -> CertLevel.CROSS;
            default -> CertLevel.UNKNOWN;
          };
      JsonMap basicConstraints = root.getMap("basicConstraints");
      if (basicConstraints == null && root.getList("extensions") != null) {
        for (JsonMap extension : root.getList("extensions").toMapList()) {
          if ("BasicConstraints".equalsIgnoreCase(extension.getString("type"))) {
            basicConstraints = extension.getMap("basicConstraints");
            break;
          }
        }
      }
      Integer pathLen = null;
      if (basicConstraints != null && basicConstraints.getKeys().contains("pathLen")) {
        Object value = basicConstraints.getObject("pathLen");
        if (!(value instanceof Long || value instanceof Integer)
            || ((Number) value).longValue() < 0
            || ((Number) value).longValue() > Integer.MAX_VALUE) {
          return unknown("Invalid profile path length");
        }
        pathLen = ((Number) value).intValue();
      }
      Set<String> algorithms = new LinkedHashSet<>();
      if (root.getList("keyAlgorithms") != null) {
        algorithms.addAll(root.getList("keyAlgorithms").toStringList());
      }
      return new ProfileCapabilities(
          level,
          pathLen,
          Set.copyOf(algorithms),
          level == CertLevel.UNKNOWN ? "Unsupported or missing certLevel" : null);
    } catch (Exception ex) {
      return unknown("Certificate profile configuration is invalid");
    }
  }

  private static ProfileCapabilities unknown(String message) {
    return new ProfileCapabilities(CertLevel.UNKNOWN, null, Set.of(), message);
  }
}
