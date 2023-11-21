// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.JSON;
import org.xipki.util.exception.InvalidConfException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;

/**
 * JSON util class for CA
 *
 * @author Lijun Liao (xipki)
 */
public class CaJson {

  private static class X509CertSerializer extends JsonSerializer<X509Cert> {

    @Override
    public void serialize(X509Cert value, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
        throws IOException {
      jsonGenerator.writeString(Base64.encodeToString(value.getEncoded()));
    }

  }

  private static class X509CertDeserializer extends JsonDeserializer<X509Cert> {

    @Override
    public X509Cert deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
        throws IOException {
      try {
        return X509Util.parseCert(Base64.decode(jsonParser.getValueAsString()));
      } catch (CertificateEncodingException e) {
        throw new IOException("invalid base64 certificate", e);
      }
    }

  }

  private static class CrlControlSerializer extends JsonSerializer<CrlControl> {

    @Override
    public void serialize(CrlControl value, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
        throws IOException {
      jsonGenerator.writeObject(value. getConfPairs().asMap());
    }

  }

  private static class CrlControlDeserializer extends JsonDeserializer<CrlControl> {

    @Override
    public CrlControl deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
        throws IOException {
      try {
        return new CrlControl(JSON.deserializerConfPairs(jsonParser));
      } catch (InvalidConfException e) {
        throw new IOException("invalid CrlControl", e);
      }
    }

  }

  private static class CtlogControlSerializer extends JsonSerializer<CtlogControl> {

    @Override
    public void serialize(CtlogControl value, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
        throws IOException {
      jsonGenerator.writeObject(value.getConfPairs().asMap());
    }

  }

  private static class CtlogControlDeserializer extends JsonDeserializer<CtlogControl> {

    @Override
    public CtlogControl deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
        throws IOException {
      try {
        return new CtlogControl(JSON.deserializerConfPairs(jsonParser));
      } catch (InvalidConfException e) {
        throw new IOException("invalid CrlControl", e);
      }
    }

  }

  private static class RevokeSuspendedControlSerializer extends JsonSerializer<RevokeSuspendedControl> {

    @Override
    public void serialize(RevokeSuspendedControl value, JsonGenerator jsonGenerator,
                          SerializerProvider serializerProvider)
        throws IOException {
      jsonGenerator.writeObject(value.getConfPairs().asMap());
    }

  }

  private static class RevokeSuspendedControlDeserializer extends JsonDeserializer<RevokeSuspendedControl> {

    @Override
    public RevokeSuspendedControl deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
        throws IOException {
      return new RevokeSuspendedControl(JSON.deserializerConfPairs(jsonParser));
    }

  }

  private static class XiCaJsonModule extends SimpleModule {

    public static final XiCaJsonModule INSTANCE = new XiCaJsonModule();
    public XiCaJsonModule() {
      addSerializer  (X509Cert.class, new X509CertSerializer());
      addDeserializer(X509Cert.class, new X509CertDeserializer());

      addSerializer  (CrlControl.class, new CrlControlSerializer());
      addDeserializer(CrlControl.class, new CrlControlDeserializer());

      addSerializer  (CtlogControl.class, new CtlogControlSerializer());
      addDeserializer(CtlogControl.class, new CtlogControlDeserializer());

      addSerializer  (RevokeSuspendedControl.class, new RevokeSuspendedControlSerializer());
      addDeserializer(RevokeSuspendedControl.class, new RevokeSuspendedControlDeserializer());
    }

  }

  private static final ObjectMapper mapper;
  private static final ObjectWriter prettyWriter;

  static {
    mapper = newDefaultObjectMapper();
    prettyWriter = newDefaultObjectMapper().writerWithDefaultPrettyPrinter();
  }

  public static ObjectMapper newDefaultObjectMapper() {
    return JSON.newDefaultObjectMapper().registerModule(XiCaJsonModule.INSTANCE);
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

}
