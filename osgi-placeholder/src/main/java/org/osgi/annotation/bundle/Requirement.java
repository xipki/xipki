// #THIRDPARTY
// Copyright (c) Contributors to the Eclipse Foundation
// License: Apache-2.0

package org.osgi.annotation.bundle;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Documented
@Retention(RetentionPolicy.CLASS)
@Target({
    ElementType.TYPE, ElementType.PACKAGE
})
@Repeatable(Requirements.class)
public @interface Requirement {

  String namespace();

  String name() default "";

  String version() default "";

  String filter() default "";

  String effective() default "resolve"; // Namespace.EFFECTIVE_RESOLVE

  String[] attribute() default {};

  String cardinality() default Cardinality.SINGLE;

  final class Cardinality {
    public static final String    SINGLE   = "SINGLE";   // Namespace.CARDINALITY_SINGLE
    public static final String    MULTIPLE = "MULTIPLE"; // Namespace.CARDINALITY_MULTIPLE
  }

  String resolution() default Resolution.MANDATORY;

  final class Resolution {
    public static final String MANDATORY = "MANDATORY"; // Namespace.RESOLUTION_MANDATORY
    public static final String OPTIONAL  = "OPTIONAL";  // Namespace.RESOLUTION_OPTIONAL
  }

}
