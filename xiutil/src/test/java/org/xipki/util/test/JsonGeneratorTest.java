// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;

/**
 * Test for JSON.
 *
 * @author Lijun Liao (xipki)
 */

public class JsonGeneratorTest {

  @Test
  public void test() throws Exception {
    JsonMap root = new JsonMap();
    JsonList textList = new JsonList();
    textList.add("a");
    textList.add("b");
    root.put("textList", textList);

    JsonList longList = new JsonList();
    longList.add(1);
    longList.add(2);
    root.put("longList", longList);

    root.put("emptyList", new JsonList());

    root.put("int", 1);
    root.put("str", "text");
    root.put("null", (String) null);

    JsonMap l1Map = new JsonMap();
    l1Map.put("l1-1", "v-l1-1");
    l1Map.put("l1-2", "v-l1-2");
    root.put("l1map", l1Map);

    JsonList mixList = new JsonList();
    mixList.add(1);
    mixList.add("text");

    JsonMap map0 = new JsonMap();
    mixList.add(map0);

    JsonMap map1 = new JsonMap();
    map1.put("m1-k1", "v-k1");
    map1.put("m1-k2", "v-k2");
    mixList.add(map1);

    JsonMap map2 = new JsonMap();
    map2.put("m2-k1", "v-k1");
    map2.put("m2-k2", "v-k2");
    mixList.add(map2);

    root.put("mixList", mixList);

    JsonList mapList = new JsonList();
    mapList.add(map0);
    mapList.add(map1);
    mapList.add(map2);
    root.put("mapList", mapList);

    JsonList listList = new JsonList();
    JsonList subList1 = new JsonList();
    subList1.add("a1");
    subList1.add("b1");
    subList1.add("c1");

    JsonList subList2 = new JsonList();
    subList2.add("a2");
    subList2.add("b2");
    subList2.add("c2");
    listList.add(subList1);
    listList.add(subList2);
    root.put("listList", listList);

    String encoded = JsonBuilder.toJson(root);
    System.out.println(encoded);

    System.out.println("------");
    encoded = JsonBuilder.toPrettyJson(root);
    System.out.println(encoded);

    JsonMap dmap = JsonParser.parseMap(encoded, false);
    Assert.assertNotNull("textList", dmap.getList("textList"));
    Assert.assertNotNull("TEXTList", dmap.getList("TextList"));
  }

  @Test
  public void testUtf8() throws Exception {
    JsonMap root = new JsonMap();
    root.put("utf8-text", "你好");
    String encoded = JsonBuilder.toJson(root);
    System.out.println(encoded);

    JsonMap root2 = JsonParser.parseMap(encoded, false);
    String encoded2 = JsonBuilder.toJson(root2);
    System.out.println(encoded2);
  }

}
