// License Apache License 2.0

package org.xipki.mgmt.web.core;

import java.lang.reflect.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.time.temporal.TemporalAccessor;
import java.util.*;
import org.xipki.codec.json.*;
import org.xipki.mgmt.web.core.JsonSyntax.Shape;
import org.xipki.mgmt.web.security.RoleBinding;
import org.xipki.mgmt.web.security.WebPrincipal;

/**
 * XiPKI JSON codec with a narrow adapter for this application's DTOs and records.
 *
 * @author palos
 */
public final class Json {
  public static <T> T read(String text, Class<T> type) {
    try {
      Shape shape = JsonSyntax.validate(text);
      Object nativeValue =
          JsonParser.parseMap("{\"value\":" + text + "}", false).getObject("value");
      return type.cast(convert(plain(nativeValue, shape), type));
    } catch (IllegalArgumentException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new IllegalArgumentException("Invalid JSON request", ex);
    }
  }

  public static String write(Object value) {
    Object nativeValue = nativeValue(value, 0);
    JsonBuilder compact = new JsonBuilder(false, null, false);
    if (nativeValue instanceof JsonMap map) {
      return compact.doToJson(map);
    }
    if (nativeValue instanceof JsonList list) {
      return compact.doToJson(list);
    }
    // The codec root API accepts containers; wrapping also preserves scalar encoding.
    String wrapped = compact.doToJson(new JsonMap(Collections.singletonMap("v", nativeValue)));
    return wrapped.substring(5, wrapped.length() - 1);
  }

  public static void validateSyntax(String text) {
    JsonSyntax.validate(text);
  }

  public static byte[] bytes(Object value) {
    return write(value).getBytes(StandardCharsets.UTF_8);
  }

  private static Object plain(Object value, Shape shape) {
    if (shape.fields() != null) {
      Map<String, Object> result = new LinkedHashMap<>();
      for (var entry : shape.fields().entrySet()) {
        result.put(
            entry.getKey(),
            plain(
                value instanceof JsonMap map ? map.getObject(entry.getKey()) : null,
                entry.getValue()));
      }
      return result;
    }
    if (shape.items() != null) {
      List<Object> result = new ArrayList<>();
      if (value == null) {
        return null;
      }
      JsonList list = (JsonList) value;
      for (int i = 0; i < shape.items().size(); i++) {
        result.add(plain(list.getAt(i), shape.items().get(i)));
      }
      return result;
    }
    return value;
  }

  private static Object convert(Object value, Type type) throws ReflectiveOperationException {
    if (type instanceof ParameterizedType parameterized) {
      Type raw = parameterized.getRawType();
      if (raw == List.class || raw == Collection.class || raw == Set.class) {
        if (value == null) {
          return null;
        }
        if (!(value instanceof List<?> list)) {
          throw invalid();
        }
        Collection<Object> result = raw == Set.class ? new LinkedHashSet<>() : new ArrayList<>();
        for (Object item : list) {
          result.add(convert(item, parameterized.getActualTypeArguments()[0]));
        }
        return result;
      }
      if (raw == Map.class) {
        if (value == null) {
          return null;
        }
        if (!(value instanceof Map<?, ?> map)
            || parameterized.getActualTypeArguments()[0] != String.class) {
          throw invalid();
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (var entry : map.entrySet()) {
          result.put(
              (String) entry.getKey(),
              convert(entry.getValue(), parameterized.getActualTypeArguments()[1]));
        }
        return result;
      }
      return convert(value, raw);
    }
    if (!(type instanceof Class<?> cls)) {
      throw invalid();
    }
    if (value == null) {
      if (!cls.isPrimitive()) {
        return null;
      }
      if (cls == boolean.class) {
        return false;
      }
      if (cls == long.class) {
        return 0L;
      }
      if (cls == int.class) {
        return 0;
      }
      throw invalid();
    }
    if (cls == Object.class || cls == Map.class || cls == List.class) {
      if (cls != Object.class && !cls.isInstance(value)) {
        throw invalid();
      }
      return value;
    }
    if (cls == String.class) {
      if (!(value instanceof String)) {
        throw invalid();
      }
      return value;
    }
    if (cls == boolean.class || cls == Boolean.class) {
      if (!(value instanceof Boolean)) {
        throw invalid();
      }
      return value;
    }
    if (cls == int.class || cls == Integer.class || cls == long.class || cls == Long.class) {
      if (!(value instanceof Long || value instanceof Integer)) {
        throw invalid();
      }
      long number = ((Number) value).longValue();
      if (cls == int.class || cls == Integer.class) {
        if (number < Integer.MIN_VALUE || number > Integer.MAX_VALUE) {
          throw invalid();
        }
        return (int) number;
      }
      return number;
    }
    if (cls == Instant.class && value instanceof String text) {
      return Instant.parse(text);
    }
    if (cls.isEnum() && value instanceof String text) {
      @SuppressWarnings({"unchecked", "rawtypes"})
      Object result = Enum.valueOf((Class) cls, text);
      return result;
    }
    if (!(value instanceof Map<?, ?> map)) {
      throw invalid();
    }
    if (cls.isRecord()) {
      RecordComponent[] parts = cls.getRecordComponents();
      Set<String> names = new HashSet<>();
      Object[] args = new Object[parts.length];
      Class<?>[] types = new Class<?>[parts.length];
      for (int i = 0; i < parts.length; i++) {
        names.add(parts[i].getName());
        types[i] = parts[i].getType();
        args[i] = convert(map.get(parts[i].getName()), parts[i].getGenericType());
      }
      if (!names.containsAll(map.keySet())) {
        throw invalid();
      }
      return cls.getDeclaredConstructor(types).newInstance(args);
    }
    Object dto = cls.getDeclaredConstructor().newInstance();
    Map<String, Field> fields = new LinkedHashMap<>();
    for (Field field : cls.getFields()) {
      if (!Modifier.isStatic(field.getModifiers())) {
        fields.put(field.getName(), field);
      }
    }
    for (var entry : map.entrySet()) {
      Field field = fields.get(entry.getKey());
      if (field == null) {
        throw invalid();
      }
      field.set(dto, convert(entry.getValue(), field.getGenericType()));
    }
    return dto;
  }

  private static Object nativeValue(Object value, int depth) {
    if (depth > 128) {
      throw invalid();
    }
    if (value == null
        || value instanceof String
        || value instanceof Boolean
        || value instanceof Integer
        || value instanceof Long
        || value instanceof Short
        || value instanceof Byte) {
      return value;
    }
    if (value instanceof Double number) {
      if (!Double.isFinite(number)) {
        throw invalid();
      }
      return value;
    }
    if (value instanceof Float number) {
      if (!Float.isFinite(number)) {
        throw invalid();
      }
      return value;
    }
    if (value instanceof BigInteger number) {
      return number.longValueExact();
    }
    if (value instanceof TemporalAccessor || value instanceof UUID) {
      return value.toString();
    }
    if (value instanceof Date date) {
      return date.getTime();
    }
    if (value instanceof Enum<?> enumeration) {
      return enumeration.name();
    }
    if (value instanceof byte[] bytes) {
      return Base64.getEncoder().encodeToString(bytes);
    }
    if (value instanceof JsonMap || value instanceof JsonList) {
      return value;
    }
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> result = new LinkedHashMap<>();
      for (var entry : map.entrySet()) {
        if (!(entry.getKey() instanceof String key)) {
          throw invalid();
        }
        result.put(key, nativeValue(entry.getValue(), depth + 1));
      }
      return new JsonMap(result);
    }
    if (value instanceof Iterable<?> iterable) {
      JsonList result = new JsonList();
      for (Object item : iterable) {
        result.addObject(nativeValue(item, depth + 1));
      }
      return result;
    }
    if (value.getClass().isArray()) {
      JsonList result = new JsonList();
      for (int i = 0; i < Array.getLength(value); i++) {
        result.addObject(nativeValue(Array.get(value, i), depth + 1));
      }
      return result;
    }
    if (!value.getClass().getName().startsWith("org.xipki.mgmt.web.")
        || value instanceof WebPrincipal) {
      throw invalid();
    }
    Map<String, Object> fields = new LinkedHashMap<>();
    try {
      if (value.getClass().isRecord()) {
        for (RecordComponent part : value.getClass().getRecordComponents()) {
          // Role definitions are returned separately in rolePermissions, as in the original API.
          if (value instanceof RoleBinding && part.getName().equals("definition")) {
            continue;
          }
          fields.put(part.getName(), nativeValue(part.getAccessor().invoke(value), depth + 1));
        }
      } else {
        for (Class<?> cls = value.getClass(); cls != Object.class; cls = cls.getSuperclass()) {
          for (Field field : cls.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers())
                || field.isSynthetic()
                || fields.containsKey(field.getName())) {
              continue;
            }
            Object property;
            if (Modifier.isPublic(field.getModifiers())) {
              property = field.get(value);
            } else {
              String name =
                  Character.toUpperCase(field.getName().charAt(0)) + field.getName().substring(1);
              Method getter;
              try {
                getter = value.getClass().getMethod("get" + name);
              } catch (NoSuchMethodException ex) {
                try {
                  getter = value.getClass().getMethod("is" + name);
                } catch (NoSuchMethodException absent) {
                  continue;
                }
              }
              property = getter.invoke(value);
            }
            fields.put(field.getName(), nativeValue(property, depth + 1));
          }
        }
      }
      return new JsonMap(fields);
    } catch (ReflectiveOperationException ex) {
      throw new IllegalArgumentException("Unsupported JSON value", ex);
    }
  }

  private static IllegalArgumentException invalid() {
    return new IllegalArgumentException("Invalid JSON fields or types");
  }

  private Json() {}
}
