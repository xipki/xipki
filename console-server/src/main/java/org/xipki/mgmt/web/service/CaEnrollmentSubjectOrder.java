// License Apache License 2.0

package org.xipki.mgmt.web.service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import org.xipki.codec.json.JsonList;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.mgmt.web.ca.CaDomain.CaMgmtException;
import org.xipki.mgmt.web.ca.CaDomain.CertprofileEntry;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.core.ApiException;

/**
 * Checks the RDN order XiPKI's profile will use before an irreversible issuance.
 *
 * @author palos
 */
public final class CaEnrollmentSubjectOrder {
  private static final List<String> DEFAULT_ORDER =
      List.of(
          "2.5.4.6",
          "0.9.2342.19200300.100.1.25",
          "2.5.4.8",
          "2.5.4.7",
          "2.5.4.17",
          "2.5.4.9",
          "2.5.4.16",
          "1.3.6.1.4.1.311.60.2.1.3",
          "1.3.6.1.4.1.311.60.2.1.2",
          "1.3.6.1.4.1.311.60.2.1.1",
          "2.5.4.10",
          "2.5.4.97",
          "1.3.6.1.4.1.18838.1.1",
          "1.3.6.1.4.1.4710.1.3.2",
          "2.5.4.11",
          "2.5.4.5",
          "2.5.4.4",
          "2.5.4.43",
          "2.5.4.42",
          "2.5.4.12",
          "2.5.4.65",
          "2.5.4.41",
          "2.5.4.3",
          "0.9.2342.19200300.100.1.1",
          "2.5.4.54",
          "1.2.840.113549.1.9.1",
          "1.2.840.113549.1.9.2",
          "1.2.840.113549.1.9.8",
          "2.5.4.20",
          "2.5.4.15");
  private static final Map<String, String> TYPES = types();

  private CaEnrollmentSubjectOrder() {}

  public static void requireMatch(CaManager manager, String profile, X500Principal subject)
      throws CaMgmtException {
    requireMatch(manager, profile, subject, DEFAULT_ORDER);
  }

  public static List<String> parseOrder(String configured) {
    if (configured == null || configured.isBlank()) {
      return DEFAULT_ORDER;
    }
    List<String> order = new ArrayList<>();
    for (String raw : configured.split(",", -1)) {
      String type = raw.trim();
      if (!type.matches("[0-9]+(?:\\.[0-9]+)+") || order.contains(type)) {
        throw new IllegalArgumentException("Invalid XIPKI_CA_RDN_ORDER");
      }
      order.add(type);
    }
    return List.copyOf(order);
  }

  public static void requireMatch(
      CaManager manager, String profile, X500Principal subject, List<String> caOrder)
      throws CaMgmtException {
    CertprofileEntry entry = manager.getCertprofile(profile);
    if (entry == null || entry.isFaulty() || !"xijson".equalsIgnoreCase(entry.getType())) {
      throw new ApiException(400, "Cannot validate certificate profile subject order");
    }
    try {
      JsonMap config = JsonParser.parseMap(entry.getConf(), false);
      Object raw = config.getObject("subject");
      JsonList fields;
      boolean keepOrder;
      if (raw instanceof JsonList list) {
        fields = list;
        keepOrder = config.getBool("keepSubjectOrder", false);
      } else if (raw instanceof JsonMap map) {
        fields = map.getNnList("rdns");
        keepOrder = map.getBool("keepRdnOrder", false);
      } else {
        throw new IllegalArgumentException("Cannot validate certificate profile subject order");
      }
      List<String> profileTypes = new ArrayList<>();
      for (JsonMap field : fields.toMapList()) {
        if (field.getObject("value") != null) {
          throw new ApiException(
              400,
              "Certificate profile has a fixed subject value; online SubCA issuance cannot safely"
                  + " verify the issued subject");
        }
        Object type = field.getObject("type");
        if (type instanceof JsonMap typeMap) {
          type = typeMap.getString("oid");
        }
        profileTypes.add(oid((String) type));
      }
      if (!keepOrder) {
        profileTypes.sort(Comparator.comparingInt(type -> position(type, caOrder)));
      }
      List<String> requestedTypes = new ArrayList<>();
      for (Rdn rdn : new LdapName(subject.getName(X500Principal.RFC2253)).getRdns()) {
        if (rdn.size() != 1) {
          throw new ApiException(400, "Cannot validate multi-valued CSR subject order");
        }
        requestedTypes.add(oid(rdn.getType()));
      }
      List<String> expectedTypes = new ArrayList<>();
      for (String type : new LinkedHashSet<>(profileTypes)) {
        for (String requested : requestedTypes) {
          if (type.equals(requested)) {
            expectedTypes.add(type);
          }
        }
      }
      if (!expectedTypes.equals(requestedTypes)) {
        throw new ApiException(
            400,
            "CSR subject order does not match the certificate profile; enter the DN in reverse"
                + " profile order");
      }
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ApiException(400, "Cannot validate certificate profile subject order");
    }
  }

  private static int position(String oid, List<String> order) {
    int index = order.indexOf(oid);
    return index < 0 ? order.size() : index;
  }

  private static String oid(String name) {
    if (name == null) {
      throw new IllegalArgumentException("Cannot validate certificate profile subject order");
    }
    String oid = TYPES.get(name.toLowerCase(Locale.ROOT));
    if (oid != null) {
      return oid;
    }
    if (name.matches("[0-9]+(?:\\.[0-9]+)+")) {
      return name;
    }
    throw new IllegalArgumentException(
        "Cannot validate certificate profile subject order: unsupported RDN type " + name);
  }

  private static Map<String, String> types() {
    Map<String, String> names = new HashMap<>();
    alias(names, "2.5.4.6", "C", "country");
    alias(names, "2.5.4.8", "ST", "state");
    alias(names, "2.5.4.7", "L", "locality");
    alias(names, "2.5.4.9", "STREET", "street");
    alias(names, "2.5.4.10", "O", "organization");
    alias(names, "2.5.4.11", "OU", "organizationalUnit", "organizationUnit");
    alias(names, "2.5.4.5", "SERIALNUMBER", "SN", "serialNumber");
    alias(names, "2.5.4.3", "CN", "commonName");
    alias(names, "2.5.4.4", "SURNAME", "surname");
    alias(names, "2.5.4.42", "GIVENNAME", "GN", "givenName");
    alias(names, "2.5.4.12", "T", "title");
    alias(names, "2.5.4.97", "organizationIdentifier", "OI");
    alias(names, "0.9.2342.19200300.100.1.25", "DC", "domainComponent");
    alias(names, "0.9.2342.19200300.100.1.1", "UID", "userid");
    alias(names, "1.2.840.113549.1.9.1", "EMAILADDRESS", "E", "emailAddress", "email");
    alias(names, "2.5.4.15", "businessCategory");
    alias(names, "2.5.4.17", "postalCode");
    alias(names, "2.5.4.16", "postalAddress");
    alias(names, "2.5.4.20", "telephoneNumber", "telephone");
    return Map.copyOf(names);
  }

  private static void alias(Map<String, String> names, String oid, String... aliases) {
    for (String alias : aliases) {
      names.put(alias.toLowerCase(Locale.ROOT), oid);
    }
  }
}
