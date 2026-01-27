// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.codec;

import java.util.Map;

/**
 * Variable resolver.
 *
 * @author Lijun Liao (xipki)
 */
public interface VariableResolver {

  String resolve(String text);

  class MapVariableResolver implements VariableResolver {

    private final Map<String, String> nameValueMap;

    public MapVariableResolver(Map<String, String> nameValueMap) {
      this.nameValueMap = Args.notNull(nameValueMap, "nameValueMap");
    }

    @Override
    public String resolve(String text) {
      if (text == null || !text.contains("${") || text.indexOf('}') == -1) {
        return text;
      }

      for (Map.Entry<String, String> entry : nameValueMap.entrySet()) {
        String name = entry.getKey();
        String placeHolder = "${" + name + "}";
        while (text.contains(placeHolder)) {
          text = text.replace(placeHolder, entry.getValue());
        }
      }

      return text;
    }

  }

}
