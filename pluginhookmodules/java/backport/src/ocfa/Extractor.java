package ocfa;

/**
 * interface for classes that can be used java components in extractor
 * modules in the washing machine.
 *
 */

public interface Extractor {


    /**
     * processes the evidence in an extractor-like sort of way.
     * @param inFile. the file of which metadata should be extracted.
     * @return the 
     *
     */
    String [] processEvidence(String inFile);

}