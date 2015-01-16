Identity4j is a java library for interacting with the UFP Identity service. UFP Identity provides strong, flexible, user login for your website.

To get started, build the javadocs using:

    mvn clean javadoc:aggregate

The javadoc overview provides details about how to use the library.

Installing the Identity4j .jar to your local repo:

    mvn clean install

Coming soon: a .jsp example of exactly how to use the library standalone

For maven, add the following dependency to your dependency section:

    <dependency>
      <groupId>com.ufp</groupId>
      <artifactId>identity4j</artifactId>
      <version>1.2.0</version>
    </dependency>

and the following repository to your repositories section:

    <repository>
      <id>maven2-repository.ufp.com</id>
      <name>UFP Identity Repository for Maven</name>
      <url>http://repo.ufp.com/maven2/</url>
      <layout>default</layout>
    </repository>