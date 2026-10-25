// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.id;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.asn1.oid.MatterOIDs;
import org.xipki.codec.util.Args;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Attribute Type definition.
 *
 * @author Lijun Liao (xipki)
 */
public class AttributeType extends AbstractID {

  private static final Map<String, AttributeType> typeMap = new HashMap<>();

  public static final AttributeType emailAddress =
      initOf(AttributeOIDs.emailAddress, "emailAddress", "E", "email");

  public static final AttributeType email = emailAddress;

  public static final AttributeType commonName =
      initOf(AttributeOIDs.commonName, "commonName", "CN");

  public static final AttributeType CN = commonName;

  public static final AttributeType surname =
      initOf(AttributeOIDs.surname, "surname");

  public static final AttributeType serialNumber =
      initOf(AttributeOIDs.serialNumber, "serialNumber", "SN");

  public static final AttributeType SN = serialNumber;

  public static final AttributeType country =
      initOf(AttributeOIDs.country, "country", "C");

  public static final AttributeType C = country;

  public static final AttributeType locality =
      initOf(AttributeOIDs.locality, "locality", "L");

  public static final AttributeType L = locality;

  public static final AttributeType state = initOf(AttributeOIDs.state);

  public static final AttributeType ST = state;

  public static final AttributeType street =
      initOf(AttributeOIDs.street, "state", "S");

  public static final AttributeType organization =
      initOf(AttributeOIDs.organization, "organization", "O");

  public static final AttributeType O = organization;

  public static final AttributeType organizationalUnit =
      initOf(AttributeOIDs.organizationalUnit, "organizationalUnit", "organizationUnit", "OU");

  public static final AttributeType OU = organizationalUnit;

  public static final AttributeType title =
      initOf(AttributeOIDs.title, "title", "T");

  public static final AttributeType businessCategory =
      initOf(AttributeOIDs.businessCategory, "businessCategory");

  public static final AttributeType givenName =
      initOf(AttributeOIDs.givenName, "givenName", "GN");

  public static final AttributeType initials =
      initOf(AttributeOIDs.initials, "initials", "I");

  public static final AttributeType generationQualifier =
      initOf(AttributeOIDs.generationQualifier, "generationQualifier");

  public static final AttributeType dnQualifier =
      initOf(AttributeOIDs.dnQualifier, "dnQualifier", "DNQ");

  public static final AttributeType pseudonym =
      initOf(AttributeOIDs.pseudonym, "pseudonym");

  public static final AttributeType organizationIdentifier =
      initOf(AttributeOIDs.organizationIdentifier, "organizationIdentifier", "OI");

  public static final AttributeType jurIncorporationLocality =
      initOf(AttributeOIDs.jurIncorporationLocality,
          "jurIncorporationLocality", "jurisdictionLocalityName", "JIL");

  public static final AttributeType jurIncorporationState =
      initOf(AttributeOIDs.jurIncorporationState,
          "jurIncorporationState", "jurisdictionStateOrProvinceName", "JIS");

  public static final AttributeType jurIncorporationCountry =
      initOf(AttributeOIDs.jurIncorporationCountry,
          "jurIncorporationCountry", "jurisdictionCountryName", "JIC");

  public static final AttributeType domainComponent =
      initOf(AttributeOIDs.domainComponent, "domainComponent", "DC");

  public static final AttributeType name =
      initOf(AttributeOIDs.name, "name");

  public static final AttributeType telephone =
      initOf(AttributeOIDs.telephoneNumber, "telephoneNumber", "telephone");

  public static final AttributeType dmdName =
      initOf(AttributeOIDs.dmdName, "dmdname");

  public static final AttributeType userid =
      initOf(AttributeOIDs.userid, "userid", "UID");

  public static final AttributeType UID = userid;

  public static final AttributeType unstructuredName =
      initOf(AttributeOIDs.unstructuredName, "unstructuredName");

  public static final AttributeType unstructuredAddress =
      initOf(AttributeOIDs.unstructuredAddress, "unstructuredAddress");

  public static final AttributeType matter_node_id =
      initOf(MatterOIDs.matter_node_id, "matter-node-id");

  public static final AttributeType matter_firmware_signing_id =
      initOf(MatterOIDs.matter_firmware_signing_id, "matter-firmware-signing-id");

  public static final AttributeType matter_icac_id =
      initOf(MatterOIDs.matter_icac_id, "matter-icac-id");

  public static final AttributeType matter_rcac_id =
      initOf(MatterOIDs.matter_rcac_id, "matter-rcac-id");

  public static final AttributeType matter_fabric_id =
      initOf(MatterOIDs.matter_fabric_id, "matter-fabric-id");

  public static final AttributeType matter_noc_cat =
      initOf(MatterOIDs.matter_noc_cat, "matter-noc_cat");

  public static final AttributeType matter_vvs_id =
      initOf(MatterOIDs.matter_vvs_id, "matter-vvs-id");

  public static final AttributeType matter_oid_vid =
      initOf(MatterOIDs.matter_oid_vid, "matter-oid-vid");

  public static final AttributeType matter_oid_pid =
      initOf(MatterOIDs.matter_oid_pid, "matter-oid-pid");

  private AttributeType(Asn1Oid x509, List<String> aliases) {
    super(x509, aliases);
  }

  private static AttributeType initOf(Asn1Oid oid, String... aliases) {
    Args.notNull(oid, "oid");
    List<String> l = new ArrayList<>();
    if (aliases != null) {
      l.addAll(Arrays.asList(aliases));
    }
    l.add(oid.getId());
    return addToMap(new AttributeType(oid, l), typeMap);
  }

  public static AttributeType ofOid(Asn1Oid oid) {
    Args.notNull(oid, "oid");
    AttributeType attr = ofOidOrName(typeMap, oid.getId());
    if (attr != null) {
      return attr;
    }

    return new AttributeType(oid, Collections.singletonList(oid.getId()));
  }

  public static AttributeType ofOidOrName(String oidOrName) {
    String c14n = canonicalizeAlias(Args.notNull(oidOrName, "oidOrName"));
    AttributeType id = ofOidOrName(typeMap, c14n);
    if (id != null) {
      return id;
    }

    try {
      Asn1Oid oid = new Asn1Oid(c14n);
      return new AttributeType(oid, Collections.singletonList(oid.getId()));
    } catch (RuntimeException e) {
      return null;
    }
  }

}
