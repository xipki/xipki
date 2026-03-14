Generate SQL files from the XML file with
https://github.com/daquino/liquify or
the forked URL
https://github.com/xipki/liquify

java -jar liquify-1.0-all.jar -t sql -db <database type> <XML-file>

Where database type is:

 h2, mysql, oracle, db2, or postgresql.

Please then copy the generated file XXX.postgresql.sql to XXX.hsqldb.sql.
