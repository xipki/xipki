// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.codec.json;

import org.xipki.util.codec.Base64;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.VariableResolver;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Codec list.
 *
 * @author Lijun Liao (xipki)
 */
public class JsonList {

  protected final List<Object> list;

  private VariableResolver variableResolver;

  public JsonList() {
    this.list = new LinkedList<>();
  }

  public void setVariableResolver(VariableResolver variableResolver) {
    this.variableResolver = variableResolver;
  }

  public int size() {
    return list.size();
  }

  public boolean withListOrMap() {
    for (Object o : list) {
      if (o instanceof JsonList || o instanceof JsonMap) {
        return true;
      }
    }
    return false;
  }

  public Object getAt(int index) {
    Object obj = list.get(index);
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

  public void add(Instant value) {
    addObject(value);
  }

  public void add(String value) {
    addObject(value);
  }

  public void add(byte[] value) {
    if (value != null) {
      add(Base64.getEncoder().encodeToString(value));
    }
  }

  public void add(Long value) {
    addObject(value);
  }

  public void add(Integer value) {
    addObject(value);
  }

  public void add(JsonMap value) {
    addObject(value);
  }

  public void add(JsonList value) {
    addObject(value);
  }

  public void addObject(Object value) {
    list.add(value);
  }

  public List<JsonMap> toMapList() throws CodecException {
    List<JsonMap> ret = new ArrayList<>(list.size());
    int index = 0;
    for (Object o : list) {
      if (o instanceof JsonMap) {
        ((JsonMap) o).setVariableResolver(variableResolver);
        ret.add((JsonMap) o);
      } else {
        throw new CodecException("The value at index " + index +
            " is not a JsonMap, but " + o.getClass().getName());
      }
      index++;
    }
    return ret;
  }

  public List<byte[]> toBytesList() throws CodecException {
    List<byte[]> ret = new ArrayList<>(list.size());
    int index = 0;
    for (Object o : list) {
      if (o instanceof String) {
        ret.add(Base64.decode((String) o));
      } else {
        throw new CodecException("The value at index " + index +
            " is not a String, but " + o.getClass().getName());
      }
      index++;
    }
    return ret;
  }

  public List<Long> toLongList() throws CodecException {
    List<Long> ret = new ArrayList<>(list.size());
    toLongCollection(ret);
    return ret;
  }

  public List<Integer> toIntList() throws CodecException {
    List<Long> lret = toLongList();
    List<Integer> ret = new ArrayList<>(lret.size());
    for (long l : lret) {
      if (l  < Integer.MIN_VALUE || l > Integer.MAX_VALUE) {
        throw new CodecException(
            "At least one value is out of range of int32");
      }
      ret.add((int) l);
    }
    return ret;
  }

  public <T extends Enum<T>> List<T> toEnumList(Class<T> clazz)
      throws CodecException {
    List<T> ret = new ArrayList<>(list.size());
    int index = 0;
    for (Object o : list) {
      if (o instanceof String) {
        String str = (String) o;
        if (variableResolver != null) {
          str = variableResolver.resolve(str);
        }
        ret.add(Enum.valueOf(clazz, str));
      } else {
        throw new CodecException("The value at index " + index +
            " is not a String, but " + o.getClass().getName());
      }
      index++;
    }
    return ret;
  }

  public List<String> toStringList() throws CodecException {
    List<String> ret = new ArrayList<>(list.size());
    toCollection(ret);
    return ret;
  }

  public Set<String> toStringSet() throws CodecException {
    Set<String> ret = new HashSet<>(list.size());
    toCollection(ret);
    return ret;
  }

  private void toCollection(Collection<String> res) throws CodecException {
    int index = 0;
    for (Object o : list) {
      if (o instanceof String) {
        String str = (String) o;
        if (variableResolver != null) {
          str = variableResolver.resolve(str);
        }

        res.add(str);
      } else {
        throw new CodecException("The value at index " + index +
            " is not a String, but " + o.getClass().getName());
      }
      index++;
    }
  }

  private void toLongCollection(Collection<Long> res) throws CodecException {
    int index = 0;
    for (Object o : list) {
      if (o instanceof Long) {
        res.add((Long) o);
      } else {
        throw new CodecException("The value at index " + index +
            " is not a Long, but " + o.getClass().getName());
      }
      index++;
    }
  }

}
