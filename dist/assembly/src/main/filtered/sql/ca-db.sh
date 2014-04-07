#!/bin/sh

COMMAND=$1

PROP_FILE=ca-db.properties
CHANGELOG_FILE=ca-init.xml
JDBC_CP=../system/mysql/mysql-connector-java/${mysql-jdbc.version}/mysql-connector-java-${mysql-jdbc.version}.jar

# retrieve the database configuration
cat ../ca-config/$PROP_FILE | sed 's/\./_/' > .$PROP_FILE
. ./.$PROP_FILE
rm .$PROP_FILE -f
echo command=$COMMAND
echo db.driverClassName=$db_driverClassName
echo db.url=$db_url
echo db.username=$db_username
#echo db.password=$db_password

liquibase/liquibase --url=$db_url --username=$db_username --password=$db_password --changeLogFile=$CHANGELOG_FILE --classpath=$JDBC_CP $COMMAND

