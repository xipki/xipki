#!/bin/sh

mvn checkstyle:checkstyle-aggregate -Dcheckstyle.config.location=xipki-checks.xml -Dcheckstyle.output.format=plain
