How to write modules that use a Java counterpart.


a Extractor 

Let your java class implement ocfa.Extractor. implement
processEvidence and make sure you have a default constructor.

Create a subclass of ocfa::java::JavaExtractor. Only implement a
constructor and a main.  In the main you create an instance of your
class and you call the initJava method of that instance. The initJava
method accepts a classpath and a className. The classpath should
contain a reference to the path in which your new class is
compiled. The classpath will automagically also include the
configuration entry java.classes in ocfa.conf. In the end the classpath should include
JavaExtractor, your derived class, and all libraries you need to run your class.

Then call run on your instance.

You will need the javamodule library to link to one of your classes.

b. Dissector 

Let your java class implement ocfa.Dissector. Implement
processEvidence and getMetaData (This class is not as much tested as
the Extractor class but did work once.).  Further it is similar as
JavaExtractor.


