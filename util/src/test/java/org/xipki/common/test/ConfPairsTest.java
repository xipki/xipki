// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.common.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.util.ConfPairs;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Test for {@link ConfPairs}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class ConfPairsTest {

  @Test
  public void test1() {
    ConfPairs pairs = new ConfPairs("key-a?", "value-a=");
    pairs.putPair("key-b", "value-b");

    String expEncoded = "key-a?=value-a\\=,key-b=value-b";
    Map<String, String> expNameValues = new HashMap<>();
    expNameValues.put("key-a?", "value-a=");
    expNameValues.put("key-b", "value-b");
    check(pairs, expEncoded, expNameValues);
  }

  @Test
  public void test2() {
    ConfPairs pairs = new ConfPairs("key-a=value-a");

    String expEncoded = "key-a=value-a";
    Map<String, String> expNameValues = new HashMap<>();
    expNameValues.put("key-a", "value-a");
    check(pairs, expEncoded, expNameValues);
  }

  @Test
  public void test3() {
    ConfPairs pairs = new ConfPairs("key-empty-value=");

    String expEncoded = "key-empty-value=";
    Map<String, String> expNameValues = new HashMap<>();
    expNameValues.put("key-empty-value", "");
    check(pairs, expEncoded, expNameValues);
  }

  @Test
  public void test4() {
    ConfPairs pairs = new ConfPairs("key-empty-value=,key-b=value-b");

    String expEncoded = "key-b=value-b,key-empty-value=";
    Map<String, String> expNameValues = new HashMap<>();
    expNameValues.put("key-b", "value-b");
    expNameValues.put("key-empty-value", "");
    check(pairs, expEncoded, expNameValues);
  }

  @Test
  public void test5() {
    ConfPairs pairs = new ConfPairs("key-a=value-a\\,");

    String expEncoded = "key-a=value-a\\,";
    Map<String, String> expNameValues = new HashMap<>();
    expNameValues.put("key-a", "value-a,");
    check(pairs, expEncoded, expNameValues);
  }

  @Test
  public void test6() {
    ConfPairs pairs = new ConfPairs("key-a=value-a\\=\\,");

    String expEncoded = "key-a=value-a\\=\\,";
    Map<String, String> expNameValues = new HashMap<>();
    expNameValues.put("key-a", "value-a=,");
    check(pairs, expEncoded, expNameValues);
  }

  @Test
  public void test7() {
    ConfPairs pairs = new ConfPairs("key-a=value-a\\=\\?");

    String expEncoded = "key-a=value-a\\=?";
    Map<String, String> expNameValues = new HashMap<>();
    expNameValues.put("key-a", "value-a=?");
    check(pairs, expEncoded, expNameValues);
  }

  private static void check(ConfPairs confPairs, String expEncoded, Map<String, String> expNameValues) {
    String isEncoded = confPairs.getEncoded();
    Assert.assertEquals("encoded", expEncoded, isEncoded);

    Set<String> isNames = confPairs.names();
    Assert.assertEquals("names", expNameValues.size(), isNames.size());

    for (String isName : isNames) {
      String expValue = expNameValues.get(isName);
      Assert.assertNotNull("name " + isName + " is not expected", expValue);
      Assert.assertEquals("value of name " + isName, expValue, confPairs.value(isName));
    }
  }

}
