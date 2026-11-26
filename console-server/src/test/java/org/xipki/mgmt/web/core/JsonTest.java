// License Apache License 2.0

package org.xipki.mgmt.web.core;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import org.junit.jupiter.api.Test;

/**
 * @author palos
 */
class JsonTest {
  public static class Input {
    public String text;
    public Integer number;
    public Boolean active;
    public List<String> names;
  }

  public record Row(long id, String text, List<String> names) {}

  @Test
  void preservesNullsFieldOrderAndRecordContracts() {
    String inputJson = "{\"text\":\"测试\",\"number\":12,\"active\":true,\"names\":[\"a\"]}";
    Input input = Json.read(inputJson, Input.class);
    assertEquals("测试", input.text);
    assertEquals(12, input.number);
    assertEquals(
        "{\"text\":null,\"number\":null,\"active\":null,\"names\":null}", Json.write(new Input()));
    assertEquals(
        new Row(42, "a", List.of("b")),
        Json.read("{\"id\":42,\"text\":\"a\",\"names\":[\"b\"]}", Row.class));
  }

  @Test
  void rejectsMalformedJsonAndTypeCoercion() {
    for (String text :
        List.of(
            "{\"number\":\"2\"}",
            "{\"number\":2147483648}",
            "{\"number\":1.5}",
            "{\"active\":\"false\"}",
            "{\"text\":true}",
            "{\"names\":[1]}",
            "{\"text\":\"a\",}",
            "{\"text\":\"a\"}{}",
            "{\"text\":\"a\" \"number\":2}",
            "{\"text\":\"a\",\"text\":\"b\"}")) {
      assertThrows(IllegalArgumentException.class, () -> Json.read(text, Input.class), text);
    }
  }

  @Test
  void preservesUnknownNullPropertiesForValidation() {
    assertThrows(IllegalArgumentException.class, () -> Json.read("{\"typo\":null}", Input.class));
    Map<?, ?> map = Json.read("{\"a\":null,\"nested\":{\"b\":null}}", Map.class);
    assertTrue(map.containsKey("a"));
    assertTrue(((Map<?, ?>) map.get("nested")).containsKey("b"));
  }

  @Test
  void boundsNestingAndRejectsInvalidStrings() {
    assertThrows(
        IllegalArgumentException.class,
        () -> Json.read("[".repeat(140) + "]".repeat(140), List.class));
    assertThrows(
        IllegalArgumentException.class, () -> Json.read("{\"text\":\"bad\nstring\"}", Input.class));
  }
}
