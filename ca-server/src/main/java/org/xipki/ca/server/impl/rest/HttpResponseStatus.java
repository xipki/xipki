/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.server.impl.rest;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HttpResponseStatus {

  public static final int CONTINUE = 100;

  public static final int SWITCHING_PROTOCOLS = 101;

  public static final int OK = 200;

  public static final int CREATED = 201;

  public static final int ACCEPTED = 202;

  public static final int NON_AUTHORITATIVE_INFORMATION = 203;

  public static final int NO_CONTENT = 204;

  public static final int RESET_CONTENT = 205;

  public static final int PARTIAL_CONTENT = 206;

  public static final int MULTIPLE_CHOICES = 300;

  public static final int MOVED_PERMANENTLY = 301;

  public static final int MOVED_TEMPORARILY = 302;

  public static final int FOUND = 302;

  public static final int SEE_OTHER = 303;

  public static final int NOT_MODIFIED = 304;

  public static final int USE_PROXY = 305;

  public static final int TEMPORARY_REDIRECT = 307;

  public static final int BAD_REQUEST = 400;

  public static final int UNAUTHORIZED = 401;

  public static final int PAYMENT_REQUIRED = 402;

  public static final int FORBIDDEN = 403;

  public static final int NOT_FOUND = 404;

  public static final int METHOD_NOT_ALLOWED = 405;

  public static final int NOT_ACCEPTABLE = 406;

  public static final int PROXY_AUTHENTICATION_REQUIRED = 407;

  public static final int REQUEST_TIMEOUT = 408;

  public static final int CONFLICT = 409;

  public static final int GONE = 410;

  public static final int LENGTH_REQUIRED = 411;

  public static final int PRECONDITION_FAILED = 412;

  public static final int REQUEST_ENTITY_TOO_LARGE = 413;

  public static final int REQUEST_URI_TOO_LONG = 414;

  public static final int UNSUPPORTED_MEDIA_TYPE = 415;

  public static final int REQUESTED_RANGE_NOT_SATISFIABLE = 416;

  public static final int EXPECTATION_FAILED = 417;

  public static final int INTERNAL_SERVER_ERROR = 500;

  public static final int NOT_IMPLEMENTED = 501;

  public static final int BAD_GATEWAY = 502;

  public static final int SERVICE_UNAVAILABLE = 503;

  public static final int GATEWAY_TIMEOUT = 504;

  public static final int HTTP_VERSION_NOT_SUPPORTED = 505;

}
