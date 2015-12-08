# Java Deserialization Scanner
Java Deserialization Scanner is a Burp Suite plugin aimed at adding active and passive detection of Java deserialization issues. It was written by Federico Dotta, a Security Expert at @ Mediaservice.net. 

Java Deserialization Scanner uses custom payloads generated with a modified version of "ysoserial", tool created by frohoff and gebl. The original tool (https://github.com/frohoff/ysoserial) generate payloads for the execution of commands on the system, using the Runtime.exec function. Usually, however, it is not possible to see the output of the command and consequently it is not simple to write a scanner based on this kind of function. The modified version (https://github.com/federicodotta/ysoserial) adds the generation of payloads that execute a syncronous sleep function, very useful to check for the presence of the Java deserialization issues in an automated way.

Currently, the passive checks of the Java Deserialiation Scanner reported the presence of serialized Java objects in the HTTP requests (in raw format or encoded in Base64) and the active checks actively scan for the presence of weak deserialization functions in conjuction with the presence of the following weak libraries:

1.	Apache Commons Collections 3 (up to 3.2.1)
2.	Apache Commons Collections 4 (up to 4.4.0)
3.	Spring (up to 4.2.2)

In the test folder there are some simple Java server applications that can be used to test the plugin. Every application employ a different vulnerable Java library.

# Author
- Federico Dotta, Security Expert at @ Mediaservice.net

# Screenshot
![alt tag](https://raw.githubusercontent.com/federicodotta/Java-Deserialization-Scanner/JavaDeserializationScanner.png)

# Installation 
1.	Download Burp Suite: http://portswigger.net/burp/download.html
2.	Install Java Deserialization Scanner from the BApp Store or follow these steps:
3.	Download the last release of Java Deserialization Scanner
4.	Open Burp -> Extender -> Extensions -> Add -> Choose JavaDeserializationScannerXX.jar file
5.	The plugin does not need any configuration

# User Guide
1.	After installation, the Java Deserialization Scanner active and passive checks will be added to the Burp Suite scanner
2.	Simply run the active or passive scanner in order to check also for weak Java deserialization

# Improving Java Deserialization Scanner
In order to improve this extension, please report any issue founded in the plugin. Furthermore if you want report me any disclosed Java library usefull for the exploitation of this weakness and, if I have the time, I will add an active check for it in my plugin.
