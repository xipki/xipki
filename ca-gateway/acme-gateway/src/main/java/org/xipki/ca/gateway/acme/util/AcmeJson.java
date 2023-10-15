/*
 * #THIRDPARTY#
 *  acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.xipki.ca.gateway.acme.util;

import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.acme.AcmeConstants;
import org.xipki.ca.gateway.acme.AcmeProtocolException;
import org.xipki.ca.gateway.acme.type.AcmeError;
import org.xipki.util.LogUtil;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * A model containing a JSON result. The content is immutable.
 * @author ACME4J team
 */
public final class AcmeJson {

    private static final Logger LOG = LoggerFactory.getLogger(AcmeJson.class);

    private final String path;

    private final Map<String, Object> data;

    /**
     * Creates a new {@link AcmeJson} root object.
     *
     * @param data
     *            {@link Map} containing the parsed JSON data
     */
    private AcmeJson(Map<String, Object> data) {
        this("", data);
    }

    /**
     * Creates a new {@link AcmeJson} branch object.
     *
     * @param path
     *            Path leading to this branch.
     * @param data
     *            {@link Map} containing the parsed JSON data
     */
    private AcmeJson(String path, Map<String, Object> data) {
        this.path = path;
        this.data = data;
    }

    /**
     * Parses JSON from byte[].
     *
     * @param bytes Bytes.
     * @return {@link AcmeJson} of the read content.
     * @throws AcmeProtocolException if error while parsing the object.
     */
    public static AcmeJson parse(byte[] bytes) throws AcmeProtocolException {
        return parse(new String(bytes, StandardCharsets.UTF_8));
    }

    /**
     * Parses JSON from a String.
     *
     * @param json JSON string
     * @return {@link AcmeJson} of the read content.
     * @throws AcmeProtocolException if error while parsing the object.
     */
    public static AcmeJson parse(String json) throws AcmeProtocolException {
        try {
            return new AcmeJson(JsonUtil.parseJson(json));
        } catch (JoseException ex) {
            LogUtil.error(LOG, ex);
            throw new AcmeProtocolException(AcmeConstants.SC_BAD_REQUEST, AcmeError.malformed, "Bad JSON: " + json);
        }
    }

    /**
     * Returns a set of all keys of this object.
     *
     * @return {@link Set} of keys.
     */
    public Set<String> keySet() {
        return Collections.unmodifiableSet(data.keySet());
    }

    /**
     * Checks if this object contains the given key.
     *
     * @param key
     *            Name of the key to check
     * @return {@code true} if the key is present
     */
    public boolean contains(String key) {
        return data.containsKey(key);
    }

    /**
     * Returns the {@link Value} of the given key.
     *
     * @param key
     *            Key to read
     * @return {@link Value} of the key
     */
    public Value get(String key) {
        return new Value(
                path.isEmpty() ? key : path + '.' + key,
                data.get(key));
    }

    /**
     * Returns the content as JSON string.
     */
    @Override
    public String toString() {
        return JsonUtil.toJson(data);
    }

    /**
     * Represents a JSON array.
     */
    public static final class Array implements Iterable<Value> {
        private final String path;
        private final List<Object> data;

        /**
         * Creates a new {@link Array} object.
         *
         * @param path
         *            JSON path to this array.
         * @param data
         *            Array data
         */
        private Array(String path, List<Object> data) {
            this.path = path;
            this.data = data;
        }

        /**
         * Returns the array size.
         *
         * @return Size of the array
         */
        public int size() {
            return data.size();
        }

        /**
         * @return {@code true} if the array is empty, {@code false} otherwise.
         */
        public boolean isEmpty() {
            return data.isEmpty();
        }

        /**
         * Gets the {@link Value} at the given index.
         *
         * @param index
         *            Array index to read from
         * @return {@link Value} at this index
         */
        public Value get(int index) {
            return new Value(path + '[' + index + ']', data.get(index));
        }

        /**
         * Returns a stream of values.
         *
         * @return {@link Stream} of all {@link Value} of this array
         */
        public Stream<Value> stream() {
            return StreamSupport.stream(spliterator(), false);
        }

        /**
         * Creates a new {@link Iterator} that iterates over the array {@link Value}.
         */
        @Override
        public Iterator<Value> iterator() {
            return new ValueIterator(this);
        }
    }

    /**
     * A single JSON value. This instance also covers {@code null} values.
     * <p>
     * All return values are never {@code null} unless specified otherwise. For optional
     * parameters, use {@link Value#optional()}.
     */
    public static final class Value {
        private final String path;
        private final Object val;

        /**
         * Creates a new {@link Value}.
         *
         * @param path
         *            JSON path to this value
         * @param val
         *            Value, may be {@code null}
         */
        private Value(String path, Object val) {
            this.path = path;
            this.val = val;
        }

        /**
         * Checks if this value is {@code null}.
         *
         * @return {@code true} if this value is present, {@code false} if {@code null}.
         */
        public boolean isPresent() {
            return val != null;
        }

        /**
         * Returns this value as {@link Optional}, for further mapping and filtering.
         *
         * @return {@link Optional} of this value, or {@link Optional#empty()} if this
         *         value is {@code null}.
         */
        public Optional<Value> optional() {
            return val != null ? Optional.of(this) : Optional.empty();
        }

        /**
         * Returns the value as {@link String}.
         * @return the value as {@link String}.
         * @throws AcmeProtocolException if the value is {@code null}.
         */
        public String asString() throws AcmeProtocolException {
            required();
            return val.toString();
        }

        /**
         * Returns the value as JSON object.
         * @return the value as JSON object.
         * @throws AcmeProtocolException if the value is not an instance of Map&lt;String, Object&gt;.
         */
        public AcmeJson asObject() throws AcmeProtocolException {
            required();
            try {
                return new AcmeJson(path, (Map<String, Object>) val);
            } catch (ClassCastException ex) {
                LogUtil.error(LOG, ex);
                throw new AcmeProtocolException(AcmeConstants.SC_BAD_REQUEST,
                    AcmeError.malformed, path + ": expected an object");
            }
        }

        /**
         * Assert the value is present.
         * @throws AcmeProtocolException if the value is {@code null}.
         */
        private void required() throws AcmeProtocolException {
            if (!isPresent()) {
                throw new AcmeProtocolException(AcmeConstants.SC_BAD_REQUEST,
                    AcmeError.malformed, path + ": required, but not set");
            }
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof Value)) {
                return false;
            }
            return Objects.equals(val, ((Value) obj).val);
        }

        @Override
        public int hashCode() {
            return val != null ? val.hashCode() : 0;
        }
    }

    /**
     * An {@link Iterator} over array {@link Value}.
     */
    private static class ValueIterator implements Iterator<Value> {
        private final Array array;
        private int index = 0;

        public ValueIterator(Array array) {
            this.array = array;
        }

        @Override
        public boolean hasNext() {
            return index < array.size();
        }

        @Override
        public Value next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }
            return array.get(index++);
        }

        @Override
        public void remove() {
            throw new UnsupportedOperationException();
        }
    }

}
