// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import com.google.gson.*;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;

/**
 * JSON util class
 *
 * @author Lijun Liao (xipki)
 * @since 6.1.0
 */
public class JSON {

  private static class ByteArrayToBase64TypeAdapter implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {
    public byte[] deserialize(JsonElement json, java.lang.reflect.Type typeOfT, JsonDeserializationContext context)
        throws JsonParseException {
      return org.xipki.util.Base64.decodeFast(json.getAsString());
    }

    public JsonElement serialize(byte[] src, java.lang.reflect.Type typeOfSrc, JsonSerializationContext context) {
      return new JsonPrimitive(org.xipki.util.Base64.encodeToString(src));
    }
  }

  private static class DoubleTypeAdapter implements JsonSerializer<Double>, JsonDeserializer<Double> {
    public Double deserialize(JsonElement json, java.lang.reflect.Type typeOfT, JsonDeserializationContext context)
        throws JsonParseException {
      return json.getAsDouble();
    }

    @Override
    public JsonElement serialize(Double aDouble, Type type, JsonSerializationContext jsonSerializationContext) {
      if (aDouble == null) {
        return null;
      }

      double d = aDouble;
      if (d == (long) d) {
        return new JsonPrimitive((long) d);
      } else {
        return new JsonPrimitive(aDouble);
      }
    }
  }

  private static class StreamAppendable implements Appendable {
    protected final OutputStream out;

    private StreamAppendable(OutputStream out) {
      this.out = out;
    }

    @Override
    public Appendable append(CharSequence csq) throws IOException {
      out.write(csq.toString().getBytes(StandardCharsets.UTF_8));
      return this;
    }

    @Override
    public Appendable append(CharSequence csq, int start, int end) throws IOException {
      out.write(csq.subSequence(start, end).toString().getBytes(StandardCharsets.UTF_8));
      return this;
    }

    @Override
    public Appendable append(char c) throws IOException {
      out.write(String.valueOf(c).getBytes(StandardCharsets.UTF_8));
      return this;
    }
  }

  private static class ByteArray extends StreamAppendable {

    private ByteArray() {
      super(new ByteArrayOutputStream(1024));
    }

    public byte[] toByteArray() {
      return ((ByteArrayOutputStream) out).toByteArray();
    }
  }

  private static final Gson gson = new GsonBuilder()
      .registerTypeHierarchyAdapter(byte[].class, new ByteArrayToBase64TypeAdapter())
      .registerTypeHierarchyAdapter(Double.class, new DoubleTypeAdapter())
      .registerTypeHierarchyAdapter(double.class, new DoubleTypeAdapter())
      .disableHtmlEscaping()
      .create();

  private static final Gson prettyGson = new GsonBuilder()
      .registerTypeHierarchyAdapter(byte[].class, new ByteArrayToBase64TypeAdapter())
      .registerTypeHierarchyAdapter(Double.class, new DoubleTypeAdapter())
      .registerTypeHierarchyAdapter(double.class, new DoubleTypeAdapter())
      .disableHtmlEscaping()
      .setPrettyPrinting().create();

  public static <T> T parseObject(String json, Class<T> classOfT) throws JsonSyntaxException {
    return gson.fromJson(json, classOfT);
  }

  public static <T> T parseObject(byte[] json, Class<T> classOfT) throws JsonSyntaxException, JsonIOException {
    return parseObject(new ByteArrayInputStream(json), classOfT);
  }

  public static <T> T parseObject(File jsonFile, Class<T> classOfT) throws JsonSyntaxException, JsonIOException {
    try {
      return parseObject(new FileInputStream(jsonFile), classOfT);
    } catch (FileNotFoundException e) {
      throw new JsonIOException(e);
    }
  }

  public static <T> T parseObject(InputStream json, Class<T> classOfT) throws JsonSyntaxException, JsonIOException {
    try (Reader reader = new InputStreamReader(json)) {
      return gson.fromJson(reader, classOfT);
    } catch (IOException e) {
      throw new JsonIOException(e);
    }
  }

  public static String toJson(Object obj) {
    return gson.toJson(obj);
  }

  public static byte[] toJSONBytes(Object obj) {
    ByteArray ba = new ByteArray();
    gson.toJson(obj, ba);
    return ba.toByteArray();
  }

  public static String toPrettyJson(Object obj) {
    return prettyGson.toJson(obj);
  }

  public static void writeJSON(Object object, OutputStream outputStream) {
    gson.toJson(object, new StreamAppendable(outputStream));
  }

  public static void writePrettyJSON(Object object, OutputStream outputStream) {
    prettyGson.toJson(object, new StreamAppendable(outputStream));
  }

}
