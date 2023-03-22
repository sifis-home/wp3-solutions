## SIFIS-HOME WP3 codebase

Joint codebase for SIFIS-HOME including ACE, EDHOC, OSCORE, Group OSCORE, and Group Joining (plus associated things).

### Building and importing

1. Run the `config.sh` script

2. Start Eclipse, then import the following projects:
  
    - californium-extended
    - ace
    - group-applications
    - edhoc-applications

3. To "ace" add the following folders to the build path:

    - californium-core
    - cf-oscore
    - element-connector
    - scandium

4. To "group-applications" add the following folders to the build path:
    - ace
    - californium-core
    - cf-oscore
    - element-connector
    - scandium

5. To "edhoc-applications" add the following folders to the build path:
    - californium-core
    - cf-edhoc
    - cf-oscore
    - element-connector

To add dependencies:

*Right click project->Properties->Java Build Path->Add...*

### Select Maven profile

If you are developing in Eclipse (and possibly other IDEs) choose the "eclipse" Maven profile for ACE:

*Right click on "ace"->Maven->Select Maven Profile...* (CTRL+Alt+P)

Deactive the "default" profile, and activate the "eclipse" profile.

*Right click on "group-applications->Maven->Select Maven Profile...* (CTRL+Alt+P)

Deactive the "default" profile, and activate the "eclipse" profile.

*Right click on "edhoc-applications"->Maven->Select Maven Profile...* (CTRL+Alt+P)

Deactive the "default" profile, and activate the "eclipse" profile.


### MySQL installation

Note that MySQL is needed for the ACE parts to run correctly. To install it use:
```
sudo apt-get install mysql-server
```

Then place a file under ace/db.pwd and group-applications/db.pwd with the database root password.


### Updating the JCE (Java Cryptography Extensions)

If some of the JUnit tests fail due to "invalid key size" you may need to update the JCE. In such case follow these instructions:

https://www.andreafortuna.org/2016/06/08/java-tips-how-to-fix-the-invalidkeyexception-illegal-key-size-or-default-parameters-runtime/


### Repository content overview

- config.sh
    - Configure and prepare projects for import in Eclipse

- test-californium.sh
    - Execute JUnit tests for Californium and save as Jacoco test reports

- test-ace.sh
    - Execute JUnit tests for ACE and save as Jacoco test reports
    - Specify the flag --with-mysql to also perform install and setup of MySQL server

- build-group-apps.sh
    - Builds DHT-enabled standalone Jar files for the Group Applications

- build-edhoc-apps.sh
    - Builds DHT-enabled standalone Jar files for the EDHOC Applications

- build-for-docker.sh
    - Prepares Docker Dockerfiles and Contexts for the Group & EDHOC Applications
    - If the flag --build-images is specified, it also builds the Docker images

- code-coverage.sh
    - Relocate Jacoco code coverage reports for deployment to gh-pages

- dht_rest_client.py
    - Allows sending volatile message to the DHT for triggering Group & EDHOC Applications
    - Run *pip install -r python_requirements.txt* to install required dependencies

- californium-extended/
    - Modified version of the Californium CoAP library with support for EDHOC and Group OSCORE

- ace/
    - Implementation of ACE with support for Group Managers and the Group Joining procedure

- group-applications/
    - **The Group Applications including:**
    - OscoreAsServer: ACE Authorization Server
    - OscoreRsServer: Group Manager (ACE Resource Server)
    - OscoreAsRsClient: Group OSCORE Server/Client which will join the group(s)
    - Adversary: Adversary for testing attacks against the group(s)

- edhoc-applications/
    - **The EDHOC Applications including:**
    - Phase0Server: CoAP-only server
    - Phase0Client: CoAP-only client
    - Phase1Server: EDHOC server using method 0 and no optimized request
    - Phase1Client: EDHOC client using method 0 and no optimized request
    - Phase2Server: EDHOC server using method 3 and no optimized request
    - Phase2Client: EDHOC client using method 3 and no optimized request
    - Phase3Server: EDHOC server using method 0 and the optimized request
    - Phase3Client: EDHOC client using method 0 and the optimized request
    - Phase4Server: EDHOC server using method 3 and the optimized request
    - Phase4Client: EDHOC client using method 3 and the optimized request

### Docker images

Docker Images for the Group & EDHOC Applications are automatically pushed to [ghcr.io](ghcr.io).

Available images are listed in the Packages section of the repository.


### Code coverage reports

Automatic code coverage reports are generated with Jacoco and can be found at the following links:

[EDHOC](https://sifis-home.github.io/wp3-solutions/reports/edhoc/) (californium-extended/cf-edhoc)

[OSCORE & Group OSCORE](https://sifis-home.github.io/wp3-solutions/reports/oscore/) (californium-extended/cf-oscore)

[ACE & Group Joining](https://sifis-home.github.io/wp3-solutions/reports/ace/) (ace)

