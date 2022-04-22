## SIFIS-HOME WP3 codebase

Joint codebase for SIFIS-HOME including ACE, EDHOC, OSCORE, Group OSCORE, and Group Joining (plus associated things).

### General steps

1. Run the `config.sh` script

2. Start Eclipse, then import the following projects:
  
    - californium-group-oscore 
    - ace

3. To "ace" add the following folders to the build path:

    - californium-core
    - element-connector
    - oscore-cf
    - scandium

To add dependencies:

Right click project->Properties->Java Build Path->Add...


### MySQL installation

Note that mySQL is needed for the ACE parts to run correctly. To install it use:
```
apt-get install mysql-server
```

Then place a file under ace/db.pwd with the database root password.


### Updating the JCE (Java Cryptography Extensions)

If some of the JUnit tests fail due to "invalid key size" you may need to update the JCE.

In such case follow these instructions:
https://www.andreafortuna.org/2016/06/08/java-tips-how-to-fix-the-invalidkeyexception-illegal-key-size-or-default-parameters-runtime/


### Support for Base64

Note that at least Java 8 must be used to have support for java.util.Base64
