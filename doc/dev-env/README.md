===== No Tab =====
1. Import the google formatter
   a. Menu Windows -> Preferences -> Java -> Code Style -> Formatter.
   b. Click Import to import the google formatter.
   3. Choose the file eclipse-java-google-style.xml 

===== Code style checker =====
1. Install plugin eclipse-cs for code style checker.
   http://eclipse-cs.sourceforge.net.
2. Windows -> Preferences -> Checkstyle -> New -> External Configuration File.
3. Fill the fields as follows
   Name: xipki_google_checks
   Location path of the file xipki_google_checks.xml.
4. Click the checker configured above asn then 'Set as Default'.
===== Import maven project in eclipse =====
1. Right click and choose 'Import', then 'Existin Maven Projects'.
2. Choose '[groupId].[artifactId]' as the 'Advanced->Name Template'.
3. Point the 'Root directory' to the project root directory.
===== Activate code style checker in eclipse =====
1. Choose the project
2. Right click and choose 'Checkstyle'
3. Choose 'Actvate Checkstyle'
