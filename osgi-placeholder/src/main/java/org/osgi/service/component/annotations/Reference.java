// #THIRDPARTY
// Copyright (c) Contributors to the Eclipse Foundation
// License: Apache-2.0

package org.osgi.service.component.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.CLASS)
@Target({
    ElementType.METHOD, ElementType.FIELD, ElementType.PARAMETER
})
public @interface Reference {
  String name() default "";

  Class<?> service() default Object.class;

  ReferenceCardinality cardinality() default ReferenceCardinality.MANDATORY;

  ReferencePolicy policy() default ReferencePolicy.STATIC;

  String target() default "";

  ReferencePolicyOption policyOption() default ReferencePolicyOption.RELUCTANT;

  ReferenceScope scope() default ReferenceScope.BUNDLE;

  String bind() default "";

  String updated() default "";

  String unbind() default "";

  String field() default "";

  FieldOption fieldOption() default FieldOption.REPLACE;

  int parameter() default 0;

  CollectionType collectionType() default CollectionType.SERVICE;
}
