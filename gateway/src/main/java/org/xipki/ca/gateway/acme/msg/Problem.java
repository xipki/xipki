// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class Problem implements JsonEncodable {

  private final String type;

  private final String detail;

  private final List<Subproblem> subproblems;

  public Problem(String type, String detail, List<Subproblem> subproblems) {
    this.type = type;
    this.detail = detail;
    this.subproblems = subproblems;
  }

  public String getType() {
    return type;
  }

  public String getDetail() {
    return detail;
  }

  public List<Subproblem> getSubproblems() {
    return subproblems;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("type", type).put("detail", detail)
        .putEncodables("subproblems", subproblems);
  }

  public static Problem parse(JsonMap json) throws CodecException {
    JsonList list = json.getList("subproblems");
    List<Subproblem> subproblems = null;
    if (list != null) {
      subproblems = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        subproblems.add(Subproblem.parse(v));
      }
    }

    return new Problem(json.getString("type"),
        json.getString("detail"), subproblems);
  }

}
