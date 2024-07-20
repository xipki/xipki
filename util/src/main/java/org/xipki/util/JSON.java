// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.TextNode;
import com.fasterxml.jackson.databind.node.ValueNode;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * JSON util class
 *
 * @author Lijun Liao (xipki)
 * @since 6.1.0
 */
public class JSON {

  private static class InstantSerializer extends JsonSerializer<Instant> {

    @Override
    public void serialize(Instant instant, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
        throws IOException {
      jsonGenerator.writeString(instant.toString());
    }

  }

  private static class InstantDeserializer extends JsonDeserializer<Instant> {

    @Override
    public Instant deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
        throws IOException {
      return Instant.parse(jsonParser.getValueAsString());
    }

  }

  private static class ValiditySerializer extends JsonSerializer<Validity> {

    @Override
    public void serialize(Validity validity, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
        throws IOException {
      jsonGenerator.writeString(validity.toString());
    }

  }

  private static class ValidityDeserializer extends JsonDeserializer<Validity> {

    @Override
    public Validity deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
        throws IOException {
      return Validity.getInstance(jsonParser.getValueAsString());
    }

  }

  private static class ConfPairsSerializer extends JsonSerializer<ConfPairs> {

    @Override
    public void serialize(ConfPairs value, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
        throws IOException {
      jsonGenerator.writeObject(value.asMap());
    }

  }

  private static class ConfPairsDeserializer extends JsonDeserializer<ConfPairs> {

    @Override
    public ConfPairs deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
        throws IOException {
      return deserializerConfPairs(jsonParser);
    }

  }

  private static class XiJsonModule extends SimpleModule {

    public static final XiJsonModule INSTANCE = new XiJsonModule();
    public XiJsonModule() {
      addSerializer  (Instant.class,  new InstantSerializer());
      addDeserializer(Instant.class,  new InstantDeserializer());

      addSerializer  (Validity.class, new ValiditySerializer());
      addDeserializer(Validity.class, new ValidityDeserializer());

      addSerializer  (ConfPairs.class, new ConfPairsSerializer());
      addDeserializer(ConfPairs.class, new ConfPairsDeserializer());
    }

  }

  private static final ObjectMapper mapper;
  private static final ObjectWriter prettyWriter;

  static {
    mapper = newDefaultObjectMapper();
    prettyWriter = newDefaultObjectMapper().writerWithDefaultPrettyPrinter();
  }

  public static ObjectMapper newDefaultObjectMapper() {
    return new ObjectMapper().registerModule(XiJsonModule.INSTANCE)
        .enable(JsonParser.Feature.ALLOW_COMMENTS)
        .enable(JsonParser.Feature.ALLOW_YAML_COMMENTS)
        .enable(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES)
        .enable(JsonParser.Feature.ALLOW_SINGLE_QUOTES)
        .enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
        .setSerializationInclusion(JsonInclude.Include.NON_NULL);
  }

  public static <T> T parseObject(String json, Class<T> classOfT) {
    try {
      return mapper.readValue(json, classOfT);
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  public static <T> T parseObject(byte[] json, Class<T> classOfT) {
    try {
      return mapper.readValue(json, classOfT);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static <T> T parseObject(Path jsonFilePath, Class<T> classOfT) throws IOException {
    return mapper.readValue(jsonFilePath.toFile(), classOfT);
  }

  public static <T> T parseObject(File jsonFile, Class<T> classOfT) throws IOException {
    return mapper.readValue(jsonFile, classOfT);
  }

  public static <T> T parseConf(byte[] json, Class<T> classOfT) {
    return parseConf(new String(json), classOfT);
  }

  public static <T> T parseConf(String json, Class<T> classOfT) {
    try {
      StringBuilder conf = new StringBuilder();
      try (BufferedReader reader = new BufferedReader(new StringReader(json))) {
        String line;
        while ((line = reader.readLine()) != null) {
          String line2 = StringUtil.resolveVariables(line);
          conf.append(line2).append("\n");
        }
      }

      return mapper.readValue(conf.toString(), classOfT);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static <T> T parseConf(File jsonFile, Class<T> classOfT) throws IOException {
    return parseConf(new String(Files.readAllBytes(jsonFile.toPath())), classOfT);
  }

  public static <T> T parseConf(Path jsonFilePath, Class<T> classOfT) throws IOException {
    return parseConf(new String(Files.readAllBytes(jsonFilePath)), classOfT);
  }

  public static <T> T parseConf(InputStream jsonInputStream, Class<T> classOfT) throws IOException {
    return parseConf(IoUtil.readAllBytes(jsonInputStream), classOfT);
  }

  /**
   * Deserialize the object from the input stream.
   * The specified stream remains open after this method returns.
   * @param jsonInputStream the input stream containing the serialized object.
   * @param classOfT the class of deserialized object.
   * @param <T> the object type of serialized object.
   * @return the serialized object
   * @throws IOException if IO error occurs while reading the stream.
   */
  public static <T> T parseObject(InputStream jsonInputStream, Class<T> classOfT) throws IOException {
    Reader noCloseReader = new InputStreamReader(jsonInputStream) {
      @Override
      public void close() {
      }
    };
    // jackson closes the stream.
    return mapper.readValue(noCloseReader, classOfT);
  }

  /**
   * Deserialize the object from the input stream and closes the inputstream.
   * The specified stream is closed after this method returns.
   * @param jsonInputStream the input stream containing the serialized object.
   * @param classOfT the class of deserialized object.
   * @param <T> the object type of serialized object.
   * @return the serialized object
   * @throws IOException if IO error occurs while reading the stream.
   */
  public static <T> T parseObjectAndClose(InputStream jsonInputStream, Class<T> classOfT) throws IOException {
    // jackson closes the stream.
    return mapper.readValue(new InputStreamReader(jsonInputStream), classOfT);
  }

  public static String toJson(Object obj) {
    try {
      return mapper.writeValueAsString(obj);
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] toJSONBytes(Object obj) {
    try {
      return mapper.writeValueAsBytes(obj);
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  public static String toPrettyJson(Object obj) {
    try {
      return prettyWriter.writeValueAsString(obj);
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Serialize the object to the output stream.
   * The specified stream remains open after this method returns.
   * @param object object to be serialized.
   * @param outputStream output stream to which the serialized object is written.
   * @throws IOException if IO error occurs while writting to the stream.
   */
  public static void writeJSON(Object object, OutputStream outputStream) throws IOException {
    outputStream.write(toJSONBytes(object));
  }

  /**
   * Serialize the object to the output stream.
   * The specified stream is closed after this method returns.
   * @param object object to be serialized.
   * @param outputStream output stream to which the serialized object is written.
   * @throws IOException if IO error occurs while writting to the stream.
   */
  public static void writeJSONAndClose(Object object, OutputStream outputStream) throws IOException {
    mapper.writeValue(outputStream, object);
  }

  /**
   * Serialize the object in pretty format to the output stream.
   * The specified stream remains open after this method returns.
   * @param object object to be serialized.
   * @param outputStream output stream to which the serialized object is written.
   * @throws IOException if IO error occurs while writting to the stream.
   */
  public static void writePrettyJSON(Object object, OutputStream outputStream) throws IOException {
    outputStream.write(toPrettyJson(object).getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Serialize the object in pretty format to the output stream.
   * The specified stream is closed after this method returns.
   * @param object object to be serialized.
   * @param outputStream output stream to which the serialized object is written.
   * @throws IOException if IO error occurs while writting to the stream.
   */
  public static void writePrettyJSONAndClose(Object object, OutputStream outputStream) throws IOException {
    prettyWriter.writeValue(outputStream, object);
  }

  public static ConfPairs deserializerConfPairs(JsonParser jsonParser) throws IOException {
    TreeNode o = jsonParser.readValueAsTree();
    if (o instanceof TextNode) {
      String text = ((TextNode) o).asText();
      return new ConfPairs(text);
    }

    Map<String, Object> map = new HashMap<>();
    Iterator<String> names = o.fieldNames();
    while (names.hasNext()) {
      String name = names.next();
      String value = ((ValueNode) o.get(name)).asText();
      map.put(name, value);
    }
    return new ConfPairs(map);
  }

}
