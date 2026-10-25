// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.id;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.asn1.oid.TcgOIDs;
import org.xipki.codec.util.Args;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Subject Directory Attribute Type definition.
 *
 * @author Lijun Liao (xipki)
 */
public class SubjectDirectoryAttributeType extends AbstractID {

  private static final Map<String, SubjectDirectoryAttributeType> typeMap = new HashMap<>();

  public static final SubjectDirectoryAttributeType title =
      initOf(AttributeOIDs.title, "title");

  public static final SubjectDirectoryAttributeType dateOfBirth =
      initOf(AttributeOIDs.dateOfBirth, "dateOfBirth");

  public static final SubjectDirectoryAttributeType placeOfBirth =
      initOf(AttributeOIDs.placeOfBirth, "placeOfBirth");

  public static final SubjectDirectoryAttributeType gender =
      initOf(AttributeOIDs.gender, "gender");

  public static final SubjectDirectoryAttributeType countryOfCitizenship =
      initOf(AttributeOIDs.countryOfCitizenship, "countryOfCitizenship");

  public static final SubjectDirectoryAttributeType countryOfResidence =
      initOf(AttributeOIDs.countryOfResidence, "countryOfResidence");

  public static final SubjectDirectoryAttributeType tcg_at_tcgPlatformSpecification =
      initOf(TcgOIDs.tcg_at_tcgPlatformSpecification, "TCG-PlatformSpecification");

  public static final SubjectDirectoryAttributeType tcg_at_tcgCredentialSpecification =
      initOf(TcgOIDs.tcg_at_tcgCredentialSpecification, "TCG-CredentialSpecification");

  public static final SubjectDirectoryAttributeType tcg_at_tcgCredentialType =
      initOf(TcgOIDs.tcg_at_tcgCredentialType, "TCG-CredentialType");

  public static final SubjectDirectoryAttributeType tcg_at_platformConfiguration_v3 =
      initOf(TcgOIDs.tcg_at_platformConfiguration_v3, "TCG-PlatformConfiguration-v3");

  public static final SubjectDirectoryAttributeType tcg_at_platformConfigUri_v3 =
      initOf(TcgOIDs.tcg_at_platformConfigUri_v3, "TCG-PlatformConfigUri-v3");

  public static final SubjectDirectoryAttributeType tcg_at_previousPlatformCertificates =
      initOf(TcgOIDs.tcg_at_previousPlatformCertificates, "TCG-PreviousPlatformCertificates");

  public static final SubjectDirectoryAttributeType tcg_at_tbbSecurityAssertions_v3 =
      initOf(TcgOIDs.tcg_at_tbbSecurityAssertions_v3, "TCG-TbbSecurityAssertions-v3");

  public static final SubjectDirectoryAttributeType tcg_at_cryptographicAnchors =
      initOf(TcgOIDs.tcg_at_cryptographicAnchors, "TCG-CryptographicAnchors");

  public static final SubjectDirectoryAttributeType tcg_at_platformOwnership =
      initOf(TcgOIDs.tcg_at_platformOwnership, "TCG-PlatformOwnership");

  public static final SubjectDirectoryAttributeType tcg_at_manufacturingAssertions =
      initOf(TcgOIDs.tcg_at_manufacturingAssertions, "TCG-ManufacturingAssertions");

  private SubjectDirectoryAttributeType(Asn1Oid x509, List<String> aliases) {
    super(x509, aliases);
  }

  private static SubjectDirectoryAttributeType initOf(Asn1Oid oid, String alias) {
    Args.notNull(oid, "oid");
    List<String> l = new ArrayList<>();
    l.add(alias);
    l.add(oid.getId());
    return addToMap(new SubjectDirectoryAttributeType(oid, l), typeMap);
  }

  public static SubjectDirectoryAttributeType ofOid(Asn1Oid oid) {
    Args.notNull(oid, "oid");
    SubjectDirectoryAttributeType attr = ofOidOrName(typeMap, oid.getId());
    if (attr != null) {
      return attr;
    }

    return new SubjectDirectoryAttributeType(oid, Collections.singletonList(oid.getId()));
  }

  public static SubjectDirectoryAttributeType ofOidOrName(String oidOrName) {
    String c14n = canonicalizeAlias(Args.notNull(oidOrName, "oidOrName"));
    SubjectDirectoryAttributeType id = ofOidOrName(typeMap, c14n);
    if (id != null) {
      return id;
    }

    try {
      Asn1Oid oid = new Asn1Oid(c14n);
      return new SubjectDirectoryAttributeType(oid, Collections.singletonList(oid.getId()));
    } catch (RuntimeException e) {
      return null;
    }
  }

}
