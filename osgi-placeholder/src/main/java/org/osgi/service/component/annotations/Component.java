// #THIRDPARTY
// Copyright (c) Contributors to the Eclipse Foundation
// License: Apache-2.0

package org.osgi.service.component.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.CLASS)
@Target(ElementType.TYPE)
@RequireServiceComponentRuntime
public @interface Component {
  String name() default "";

  Class<?>[] service() default {};

  String factory() default "";

  boolean servicefactory() default false;

  boolean enabled() default true;

  boolean immediate() default false;

  String[] property() default {};

  String[] properties() default {};

  String xmlns() default "";

  ConfigurationPolicy configurationPolicy() default ConfigurationPolicy.OPTIONAL;

  String[] configurationPid() default NAME;

  String NAME = "$";

  ServiceScope scope() default ServiceScope.DEFAULT;

  Reference[] reference() default {};

  String[] factoryProperty() default {};

  String[] factoryProperties() default {};
}
