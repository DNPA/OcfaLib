//The Open Computer Forensics Library
//Copyright (C) KLPD 2003..2006  <ocfa@dnpa.nl>
//
//This library is free software; you can redistribute it and/or
//modify it under the terms of the GNU Lesser General Public
//License as published by the Free Software Foundation; either
//version 2.1 of the License, or (at your option) any later version.
//
//This library is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//Lesser General Public License for more details.
//
//You should have received a copy of the GNU Lesser General Public
//License along with this library; if not, write to the Free Software
//Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
						
#ifndef JAVADISSECTOR_HPP
#define JAVADISSECTOR_HPP
#include "ocfa.hpp"
#include "jni.h"
#include "JavaComponent.hpp" 
namespace ocfa {
  
  namespace java {
    
    /**
     * Class that uses a java peer to handle process Evidence. 
     *
     */
    class JavaDissector : public ocfa::evidence::DissectorComponent,  protected JavaComponent {
      
    public:

      /**
       * constructor that simply calles the constructor of DissectorComponent
       * @param inName the name of the module.
       * @param inName the namespace in which the module will put the metadata. 
       */
      JavaDissector(std::string inName, std::string inNameSpace);
      
      /**
       * calls processEvidneced on the java peer. The output of that
       * method is interpreted as a path relative to the working directory. 
       * That path is then submitted. after new metadata has been hadded usinn the getMetadata method from the 
       * peer.
       *
       */
      int processEvidence();
      /**
       * initializes the java virtual machine and sets all classes.
       * @param inClassPath which is added to the java.classpath entry in ocfa.conf.
       * @param inClass the class from which an instance is used as peer.
       */
      void initJava(string inClassPath, std::string inClass);
      /**
       * empty implementation.
       */
      void processMessage(ocfa::msg::Message &msg);
      
    private:
      /**
       * the id of the processEvidence method of the dissectorComponent (peer).
       */
      jmethodID mProcessEvidenceMethodID;
      /**
       * the is of the getMetaData method of the dissector Component (peer0
       *
       */
      jmethodID mGetMetaDataID;
      /**
       * the java disscecor counterpart, also called peer, of this module.
       */
      jobject mJavaDissectorComponent;
      
    };
  }
}
#endif
