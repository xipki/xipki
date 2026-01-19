// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.id;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.OIDs;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Lijun Liao (xipki)
 */
public class AttributeType extends AbstractID {

  private static final Map<String, AttributeType> typeMap = new HashMap<>();

  public static final AttributeType emailAddress =
      initOf(OIDs.DN.emailAddress, "emailAddress", "E", "email");

  public static final AttributeType email = emailAddress;

  public static final AttributeType commonName =
      initOf(OIDs.DN.commonName, "commonName", "CN");

  public static final AttributeType CN = commonName;

  public static final AttributeType surname =
      initOf(OIDs.DN.surname, "surname");

  public static final AttributeType serialNumber =
      initOf(OIDs.DN.serialNumber, "serialNumber", "SN");

  public static final AttributeType SN = serialNumber;

  public static final AttributeType country =
      initOf(OIDs.DN.country, "country", "C");

  public static final AttributeType C = country;

  public static final AttributeType locality =
      initOf(OIDs.DN.locality, "locality", "L");

  public static final AttributeType L = locality;

  public static final AttributeType state = initOf(OIDs.DN.state);

  public static final AttributeType ST = state;

  public static final AttributeType street =
      initOf(OIDs.DN.street, "state", "S");

  public static final AttributeType organization =
      initOf(OIDs.DN.organization, "organization", "O");

  public static final AttributeType O = organization;

  public static final AttributeType organizationalUnit =
      initOf(OIDs.DN.organizationalUnit,
          "organizationalUnit", "organizationUnit", "OU");

  public static final AttributeType OU = organizationalUnit;

  public static final AttributeType title =
      initOf(OIDs.DN.title, "title", "T");

  public static final AttributeType businessCategory =
      initOf(OIDs.DN.businessCategory, "businessCategory");

  public static final AttributeType givenName =
      initOf(OIDs.DN.givenName, "givenName", "GN");

  public static final AttributeType initials =
      initOf(OIDs.DN.initials, "initials", "I");

  public static final AttributeType generationQualifier =
      initOf(OIDs.DN.generationQualifier, "generationQualifier");

  public static final AttributeType dnQualifier =
      initOf(OIDs.DN.dnQualifier, "dnQualifier", "DNQ");

  public static final AttributeType pseudonym =
      initOf(OIDs.DN.pseudonym, "pseudonym");

  public static final AttributeType organizationIdentifier =
      initOf(OIDs.DN.organizationIdentifier, "organizationIdentifier", "OI");

  public static final AttributeType jurIncorporationLocality =
      initOf(OIDs.DN.jurIncorporationLocality,
          "jurIncorporationLocality", "JIL");

  public static final AttributeType jurIncorporationState =
      initOf(OIDs.DN.jurIncorporationState, "jurIncorporationState", "JIS");

  public static final AttributeType jurIncorporationCountry =
      initOf(OIDs.DN.jurIncorporationCountry, "jurIncorporationCountry", "JIC");

  public static final AttributeType domainComponent =
      initOf(OIDs.DN.domainComponent, "domainComponent", "DC");

  public static final AttributeType postalAddress =
      initOf(OIDs.DN.postalAddress, "postalAddress");

  public static final AttributeType dateOfBirth =
      initOf(OIDs.DN.dateOfBirth, "dateOfBirth");

  public static final AttributeType name =
      initOf(OIDs.DN.name, "name");

  public static final AttributeType telephone =
      initOf(OIDs.DN.telephoneNumber, "telephoneNumber", "telephone");

  public static final AttributeType dmdName =
      initOf(OIDs.DN.dmdName, "dmdname");

  public static final AttributeType userid =
      initOf(OIDs.DN.userid, "userid", "UID");

  public static final AttributeType UID = userid;

  public static final AttributeType unstructuredName =
      initOf(OIDs.DN.unstructuredName, "unstructuredName");

  public static final AttributeType unstructuredAddress =
      initOf(OIDs.DN.unstructuredAddress, "unstructuredAddress");

  private AttributeType(
      ASN1ObjectIdentifier x509, List<String> aliases) {
    super(x509, aliases);
  }

  private static AttributeType initOf(
      ASN1ObjectIdentifier oid, String... aliases) {
    Args.notNull(oid, "oid");
    List<String> l = new ArrayList<>();
    if (aliases != null) {
      l.addAll(Arrays.asList(aliases));
    }
    l.add(oid.getId());
    return addToMap(new AttributeType(oid, l), typeMap);
  }

  public static AttributeType ofOid(ASN1ObjectIdentifier oid) {
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
      ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(c14n);
      return new AttributeType(oid, Collections.singletonList(oid.getId()));
    } catch (RuntimeException e) {
      return null;
    }
  }

}
