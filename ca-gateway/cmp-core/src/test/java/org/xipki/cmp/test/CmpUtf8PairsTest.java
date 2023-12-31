// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.cmp.CmpUtf8Pairs;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Test the {@link CmpUtf8Pairs}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CmpUtf8PairsTest {

  @Test
  public void test1() {
    CmpUtf8Pairs pairs = new CmpUtf8Pairs("key-a", "value-a");
    pairs.putUtf8Pair("key-b", "value-b");

    String expEncoded = "key-a?value-a%key-b?value-b%";
    Map<String, String> expNameValues = new HashMap<>();
    expNameValues.put("key-a", "value-a");
    expNameValues.put("key-b", "value-b");
    check(pairs, expEncoded, expNameValues);
  }

  @Test
  public void test2() {
    CmpUtf8Pairs pairs = new CmpUtf8Pairs("key-a?value-a%");

    String expEncoded = "key-a?value-a%";
    Map<String, String> expNameValues = new HashMap<>();
    expNameValues.put("key-a", "value-a");
    check(pairs, expEncoded, expNameValues);
  }

  @Test
  public void test3() {
    CmpUtf8Pairs pairs = new CmpUtf8Pairs("key-a?value-a%");

    String expEncoded = "key-a?value-a%";
    Map<String, String> expNameValues = new HashMap<>();
    expNameValues.put("key-a", "value-a");
    check(pairs, expEncoded, expNameValues);
  }

  @Test
  public void test4() {
    CmpUtf8Pairs pairs = new CmpUtf8Pairs("key-a?value-a%3f%");

    String expEncoded = "key-a?value-a%3f%";
    Map<String, String> expNameValues = new HashMap<>();
    expNameValues.put("key-a", "value-a?");
    check(pairs, expEncoded, expNameValues);
  }

  @Test
  public void test5() {
    CmpUtf8Pairs pairs = new CmpUtf8Pairs("key-a?value-a%3f%3f%25%");

    String expEncoded = "key-a?value-a%3f%3f%25%";
    Map<String, String> expNameValues = new HashMap<>();
    expNameValues.put("key-a", "value-a??%");
    check(pairs, expEncoded, expNameValues);
  }

  private static void check(CmpUtf8Pairs confPairs, String expEncoded, Map<String, String> expNameValues) {
    String isEncoded = confPairs.encoded();
    Assert.assertEquals("encoded", expEncoded, isEncoded);

    Set<String> isNames = confPairs.names();
    Assert.assertEquals("names", expNameValues.size(), isNames.size());

    for (String m : isNames) {
      String expValue = expNameValues.get(m);
      Assert.assertNotNull("name " + m + " is not expected", expValue);
      Assert.assertEquals("value of name " + m, expValue, confPairs.value(m));
    }
  }

}
