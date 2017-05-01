# Java Deserialization Scanner
Java Deserialization Scanner is a Burp Suite plugin aimed at detect and exploit Java deserialization vulnerabilities. It was written by Federico Dotta, a Security Advisor at @ Mediaservice.net. 

The plugin is made up of three different components:

1.	Integration with Burp Suite active and passive scanner
2.	Manual tester, for the detection of Java deserialization vulnerabilities on custom insertion points
3.	Exploiter, that allow to actively exploit Java deserialization vulnerabilies, using frohoff ysoserial (https://github.com/frohoff/ysoserial)

# Author
- Federico Dotta, Security Advisor at @ Mediaservice.net

# Contributors
- Jeremy Goldstein
- Andras Veres-Szentkiralyi

# Integration with Burp Suite active and passive scanner
Java Deserialization Scanner uses custom payloads generated with a modified version of "ysoserial", tool created by frohoff and gebl, to detect Java deserialization vulnerabilities. The original tool (https://github.com/frohoff/ysoserial) generate payloads for the execution of commands on the system, using the Runtime.exec function. Usually, however, it is not possible to see the output of the command and consequently it is not simple to write a scanner based on this kind of function. The modified version adds the generation of payloads that execute a syncronous sleep function, very useful to check for the presence of the Java deserialization issues in an automated way.

Currently, the passive checks of the Java Deserialiation Scanner reported the presence of serialized Java objects in the HTTP requests (in raw format or encoded in Base64 or in Ascii Hex) and the active checks actively scan for the presence of weak deserialization functions in conjuction with the presence of the following weak libraries:

1.	Apache Commons Collections 3 (up to 3.2.1), with three different chains
2.	Apache Commons Collections 4 (up to 4.4.0), with two different chains
3.	Spring (up to 4.2.2), with two different chains
4.  Java 6 and Java 7 (<= Jdk7u21) without any weak library
5.	Hibernate 5
6.	JSON
7.	Rome

In the test folder there are some simple Java server applications that can be used to test the plugin. Every application employ a different vulnerable Java library.

# Manual tester
The plugin offer a dedicated tab to launch the detection with the sleep payloads on custom insertion points, in order to check the Java deserialization vulnerabilities in particular situations in which strange entry points do not allow the detection with the scanner. The results of the manual tester can be inserted between Burp Suite scanner results.

# Exploiter
After that a Java deserialization vulnerability has been found, it is possible to actively exploit the issue with the Exploiting dedicated tab. The plugin allow to configure the path of frohoff ysoserial and use this tool to generate the exploitation payloads. The exploiter, as the other components, supports three different encodings for the payloads: raw, Base64 or Ascii Hex.

# Screenshot
![alt tag](https://raw.githubusercontent.com/federicodotta/Java-Deserialization-Scanner/master/JavaDeserializationScanner.png)

# Installation 
1.	Download Burp Suite: http://portswigger.net/burp/download.html
2.	Install Java Deserialization Scanner from the BApp Store or follow these steps:
3.	Download the last release of Java Deserialization Scanner
4.	Open Burp -> Extender -> Extensions -> Add -> Choose JavaDeserializationScannerXX.jar file

# User Guide
1.	After installation, the Java Deserialization Scanner active and passive checks will be added to the Burp Suite scanner (it is possible to disable the checks in the options tab)
2.	Simply run the active or passive scanner in order to check also for weak Java deserialization
3.  With the dedicated tab "Manual testing" it is possible to set the injection point and executing the attack with all the payloads
4.	With the dedicated tab "Exploiting" it is possibile to actively exploit Java deserialization vulnerabilites
5.	The "Configuration" contains all the needed configuration for the correct working of the plugin

# Improving Java Deserialization Scanner
In order to improve this extension, please report any issue founded in the plugin. Furthermore if you want report me any disclosed Java library usefull for the exploitation of this weakness and, if I have the time, I will add an active check for it in my plugin.

# Disclaimer
This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.
