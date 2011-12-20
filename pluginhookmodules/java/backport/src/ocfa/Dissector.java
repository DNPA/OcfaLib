package ocfa;

public interface Dissector {


    /**
     * method that takes a file and retrieves new output from it. 
     * @param inEvidencePath the file from which new files are taken.
     * @return a path relative to the working directory of the new stuff that is created 
     * from  
     *
     */
    public String processEvidence(String inEvidencePath);
    
    /**
     * methods that returns the metadata that was derived for the new entity.
     * the metadata is supposed to be in the format {"name-of-metadata", "value", "name-of-metadata", 
     * "value"}
     */
    public String[] getMetaData();

    /**
     * sets the working directory for this module.
     * @param inWorkdir the directory in which newly derived files
     * should be put.
     */
    public void setWorkDir(String inWorkDir);

    /**
     * returns the workig directory in which all new evidence should be put.
     */
    public String getWorkDir();
    
}