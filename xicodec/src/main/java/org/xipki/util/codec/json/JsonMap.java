// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.codec.json;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.Hex;
import org.xipki.util.codec.VariableResolver;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Codec map.
 *
 * @author Lijun Liao (xipki)
 */
public class JsonMap {

  protected final Map<String, Object> map;

  protected final List<String> keys;

  private VariableResolver variableResolver;

  public JsonMap() {
    this.map = new HashMap<>();
    this.keys = new LinkedList<>();
  }

  public JsonMap(Map<String, ?> map) {
    Args.notNull(map, "map");
    this.map = new HashMap<>(Args.notNull(map, "map"));
    this.keys = new LinkedList<>(map.keySet());
  }

  public void setVariableResolver(VariableResolver variableResolver) {
    this.variableResolver = variableResolver;
  }

  public int size() {
    return keys.size();
  }

  public boolean isEmpty() {
    return keys.isEmpty();
  }

  public List<String> getKeys() {
    return Collections.unmodifiableList(keys);
  }

  public JsonMap put(String key, JsonEncodable value) {
    if (value != null) {
      putObject(key, value.toCodec());
    }
    return this;
  }

  public JsonMap putStringMap(String key, Map<String, String> value) {
    if (value == null) {
      return this;
    }

    JsonMap m = new JsonMap();
    for (Map.Entry<String, String> e : value.entrySet()) {
      String v = e.getValue();
      if (v != null) {
        m.put(e.getKey(), v);
      }
    }

    putObject(key, m);
    return this;
  }

  public JsonMap put(String key, Instant value) {
    putObject(key, value);
    return this;
  }

  public JsonMap putEnum(String key, Enum<?> value) {
    if (value != null) {
      putObject(key, value.name());
    }
    return this;
  }

  public JsonMap put(String key, byte[] value) {
    if (value != null) {
      putObject(key, Base64.getEncoder().encodeToString(value));
    }
    return this;
  }

  public JsonMap put(String key, BigInteger value) {
    if (value != null) {
      putObject(key, Hex.encode(value.toByteArray()));
    }
    return this;
  }

  public JsonMap put(String key, String value) {
    putObject(key, value);
    return this;
  }

  public JsonMap put(String key, String[] value) {
    if (value != null) {
      JsonList list = new JsonList();
      for (String v : value) {
        if (v != null) {
          list.add(v);
        }
      }
      putObject(key, list);
    }
    return this;
  }

  public JsonMap put(String key, Long value) {
    putObject(key, value);
    return this;
  }

  public JsonMap put(String key, Boolean value) {
    putObject(key, value);
    return this;
  }

  public JsonMap put(String key, long[] value) {
    if (value != null) {
      JsonList list = new JsonList();
      for (long v : value) {
        list.add(v);
      }
      putObject(key, list);
    }
    return this;
  }

  public JsonMap put(String key, Integer value) {
    putObject(key, value);
    return this;
  }

  public JsonMap put(String key, int[] value) {
    if (value != null) {
      JsonList list = new JsonList();
      for (int v : value) {
        list.add(v);
      }
      putObject(key, list);
    }
    return this;
  }

  public JsonMap put(String key, JsonMap value) {
    putObject(key, value);
    return this;
  }

  public JsonMap put(String key, JsonMap[] value) {
    if (value != null) {
      JsonList list = new JsonList();
      for (JsonMap v : value) {
        if (v != null) {
          list.add(v);
        }
      }
      putObject(key, list);
    }
    return this;
  }

  public JsonMap put(String key, JsonList value) {
    putObject(key, value);
    return this;
  }

  public JsonMap putEncodables(String key,
                               Collection<? extends JsonEncodable> value) {
    if (value != null) {
      JsonList list = new JsonList();
      for (JsonEncodable v : value) {
        if (v != null) {
          list.add(v.toCodec());
        }
      }
      putObject(key, list);
    }
    return this;
  }

  public JsonMap putEnums(String key,
                          Collection<? extends Enum<?>> value) {
    if (value != null) {
      JsonList list = new JsonList();
      for (Enum<?> v : value) {
        if (v != null) {
          list.add(v.name());
        }
      }
      putObject(key, list);
    }
    return this;
  }

  public JsonMap putStrings(String key, Collection<String> value) {
    if (value != null) {
      JsonList list = new JsonList();
      for (String v : value) {
        if (v != null) {
          list.add(v);
        }
      }
      putObject(key, list);
    }
    return this;
  }

  public JsonMap putBytesCol(String key, Collection<byte[]> value) {
    if (value != null) {
      JsonList list = new JsonList();
      for (byte[] v : value) {
        if (v != null) {
          list.add(v);
        }
      }
      putObject(key, list);
    }
    return this;
  }

  protected JsonMap putObject(String key, Object value) {
    if (value != null) {
      if (keys.contains(key)) {
        throw new RuntimeException(
            "duplicated key '" + key + "'");
      }

      keys.add(key);
      map.put(key, value);
    }
    return this;
  }

  public Instant getNnInstant(String key) throws CodecException {
    return nonNull(key, getInstant(key));
  }

  public Instant getInstant(String key) throws CodecException {
    String s = getString(key);
    return (s == null) ? null : Instant.parse(s);
  }

  public String getNnString(String key) throws CodecException {
    return nonNull(key, getString(key));
  }

  public String getString(String key) throws CodecException {
    Object v = getObject(key);
    if (v == null) {
      return null;
    }

    if (!(v instanceof String)) {
      throw new CodecException("The value of " + key +
          " is not a String, but " + v.getClass().getName());
    }

    return (String) v;
  }

  public byte[] getNnBytes(String key) throws CodecException {
    return nonNull(key, getBytes(key));
  }

  public byte[] getBytes(String key) throws CodecException {
    String v = getString(key);
    if (v == null) {
      return null;
    }

    return Base64.decode(v);
  }

  public BigInteger getNnBigInteger(String key) throws CodecException {
    return nonNull(key, getBigInteger(key));
  }

  public BigInteger getBigInteger(String key) throws CodecException {
    String v = getString(key);
    if (v == null) {
      return null;
    }

    return new BigInteger(Hex.decode(v));
  }

  public List<byte[]> getNnBytesList(String key) throws CodecException {
    return nonNull(key, getBytesList(key));
  }

  public List<byte[]> getBytesList(String key) throws CodecException {
    JsonList list = getList(key);
    return list == null ? null : list.toBytesList();
  }

  public long getNnLong(String key) throws CodecException {
    return nonNull(key, getLong(key));
  }

  public Long getLong(String key) throws CodecException {
    Object v = getObject(key);
    if (v == null) {
      return null;
    }

    if (v instanceof Long) {
      return (Long) v;
    }

    throw new CodecException("The value of " + key + " is not a Long, but "
        + v.getClass().getName());
  }

  public Object getNnObject(String key) throws CodecException {
    return nonNull(key, getObject(key));
  }

  public Object getObject(String key) {
    Object obj = map.get(key);
    if (obj == null) {
      for (String k : keys) {
        if (k.equalsIgnoreCase(key)) {
          obj = map.get(k);
          break;
        }
      }

      if (obj == null) {
        return null;
      }
    }

    if (variableResolver != null) {
      if (obj instanceof String) {
        obj = variableResolver.resolve((String) obj);
      } else if (obj instanceof JsonMap) {
        ((JsonMap) obj).setVariableResolver(variableResolver);
      } else if (obj instanceof JsonList) {
        ((JsonList) obj).setVariableResolver(variableResolver);
      }
    }
    return obj;
  }

  public boolean hasObject(String key) {
    return map.containsKey(key);
  }

  public <T extends Enum<T>> List<T> getNnEnumList(
      String key, Class<T> clazz) throws CodecException {
    return nonNull(key, getEnumList(key, clazz));
  }

  public <T extends Enum<T>> List<T> getEnumList(
      String key, Class<T> clazz) throws CodecException {
    JsonList list = getList(key);
    return list == null ? null : list.toEnumList(clazz);
  }

  public <T extends Enum<T>> T getNnEnum(String key, Class<T> clazz)
      throws CodecException {
    return nonNull(key, getEnum(key, clazz));
  }

  public <T extends Enum<T>> T getEnum(String key, Class<T> clazz)
      throws CodecException {
    String str = getString(key);
    return str == null ? null : Enum.valueOf(clazz, str);
  }

  public List<Long> getNnLongList(String key) throws CodecException {
    return nonNull(key, getLongList(key));
  }

  public List<Long> getLongList(String key) throws CodecException {
    JsonList list = getList(key);
    return list == null ? null : list.toLongList();
  }

  public List<String> getNnStringList(String key) throws CodecException {
    return nonNull(key, getStringList(key));
  }

  public List<String> getStringList(String key) throws CodecException {
    JsonList list = getList(key);
    return list == null ? null : list.toStringList();
  }

  public String[] getStringArray(String key) throws CodecException {
    JsonList list = getList(key);
    return list == null ? null : list.toStringList().toArray(new String[0]);
  }

  public Set<String> getNnStringSet(String key) throws CodecException {
    return nonNull(key, getStringSet(key));
  }

  public Set<String> getStringSet(String key) throws CodecException {
    JsonList list = getList(key);
    return list == null ? null : list.toStringSet();
  }

  public JsonList getList(String key) throws CodecException {
    Object v = getObject(key);
    if (v == null) {
      return null;
    }

    if (v instanceof JsonList) {
      return (JsonList) v;
    }

    throw new CodecException("The value of " + key +
        " is not a JsonList, but " + v.getClass().getName());
  }

  public int getNnInt(String key) throws CodecException {
    return nonNull(key, getInt(key));
  }

  public Integer getInt(String key) throws CodecException {
    Long ret = getLong(key);
    if (ret == null) {
      return null;
    }

    if (ret > Integer.MAX_VALUE || ret < Integer.MIN_VALUE) {
      throw new CodecException("The value of " + key +
          " is out of the range of 32 bit integer");
    }

    return (int) (long) ret;
  }

  public int getInt(String key, int defaultValue) throws CodecException {
    Integer i = getInt(key);
    if (i == null) {
      return defaultValue;
    }
    return i;
  }

  public boolean getBool(String key, boolean defaultValue)
      throws CodecException {
    Boolean b = getBool(key);
    return b == null ? defaultValue : b;
  }

  public boolean getNnBool(String key) throws CodecException {
    return nonNull(key, getBool(key));
  }

  public Boolean getBool(String key) throws CodecException {
    Object v = getObject(key);
    if (v == null) {
      return null;
    }

    if (v instanceof Boolean) {
      return (Boolean) v;
    }

    throw new CodecException("The value of " + key +
        " is not a Boolean, but " + v.getClass().getName());
  }

  public Map<String, String> getStringMap(String key) throws CodecException {
    JsonMap map = getMap(key);
    return map == null ? null : map.toStringMap();
  }

  public JsonMap getNnMap(String key) throws CodecException {
    return nonNull(key, getMap(key));
  }

  public JsonList getNnList(String key) throws CodecException {
    return nonNull(key, getList(key));
  }

  public JsonMap getMap(String key) throws CodecException {
    Object v = getObject(key);
    if (v == null) {
      return null;
    }

    if (v instanceof JsonMap) {
      return (JsonMap) v;
    }

    throw new CodecException("The value of " + key +
        " is not a JsonMap, but " + v.getClass().getName());
  }

  public Map<String, String> toStringMap() throws CodecException {
    Map<String, String> ret = new HashMap<>(map.size());
    for (Map.Entry<String, Object> m : map.entrySet()) {
      Object v = m.getValue();
      if (v == null) {
        ret.put(m.getKey(), null);
      } else if (v instanceof String) {
        String str = (String) v;
        if (variableResolver != null) {
          str = variableResolver.resolve(str);
        }

        ret.put(m.getKey(), str);
      } else {
        throw new CodecException("The value of " + m.getKey() +
            " is not a String, but " + v.getClass().getName());
      }
    }
    return ret;
  }

  protected <T> T nonNull(String key, T value) throws CodecException {
    if (value == null) {
      throw new CodecException(key + " is not present");
    }
    return value;
  }

}
