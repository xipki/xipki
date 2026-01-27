// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.extn;

import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType;
import org.xipki.ca.certprofile.xijson.conf.extn.NameConstraints;
import org.xipki.ca.certprofile.xijsonv1.conf.V1GeneralSubtreeType;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CollectionUtil;

import java.util.ArrayList;
import java.util.List;

/**
 * Extension NameConstraints.
 * Only for CA, at least one of permittedSubtrees and excludedSubtrees must
 * be present.
 * @author Lijun Liao (xipki)
 */
public class V1NameConstraints {

  private final List<V1GeneralSubtreeType> permittedSubtrees;

  private final List<V1GeneralSubtreeType> excludedSubtrees;

  public V1NameConstraints(List<V1GeneralSubtreeType> permittedSubtrees,
                           List<V1GeneralSubtreeType> excludedSubtrees) {
    if (CollectionUtil.isEmpty(permittedSubtrees)
        && CollectionUtil.isEmpty(excludedSubtrees)) {
      throw new IllegalArgumentException(
          "permittedSubtrees and excludedSubtrees may not be both null");
    }

    this.permittedSubtrees = permittedSubtrees;
    this.excludedSubtrees = excludedSubtrees;
  }

  public NameConstraints toV2() {
    List<GeneralSubtreeType> v2PermittedSubtrees = null;
    if (this.permittedSubtrees != null) {
      v2PermittedSubtrees = new ArrayList<>(this.permittedSubtrees.size());
      for (V1GeneralSubtreeType t : this.permittedSubtrees) {
        v2PermittedSubtrees.add(t.toV2());
      }
    }

    List<GeneralSubtreeType> v2ExcludedSubtrees = null;
    if (this.excludedSubtrees != null) {
      v2ExcludedSubtrees = new ArrayList<>(this.excludedSubtrees.size());
      for (V1GeneralSubtreeType t : this.excludedSubtrees) {
        v2ExcludedSubtrees.add(t.toV2());
      }
    }

    return new NameConstraints(v2PermittedSubtrees, v2ExcludedSubtrees);
  }

  public static V1NameConstraints parse(JsonMap json) throws CodecException {
    JsonList list = json.getList("permittedSubtrees");
    List<V1GeneralSubtreeType> permittedSubtrees = (list == null) ? null
        : V1GeneralSubtreeType.parseList(list);

    list = json.getList("excludedSubtrees");
    List<V1GeneralSubtreeType> excludedSubtrees = (list == null) ? null
        : V1GeneralSubtreeType.parseList(list);

    return new V1NameConstraints(permittedSubtrees, excludedSubtrees);
  }

}
