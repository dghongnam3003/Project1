package com.hust.cysec.vtapi;

import java.io.IOException;
import java.util.*;

public class App 
{
    public final static String API_KEY = "ffefe1cf95c72be26918974d944179629816e48e7590c64f484b43dbc2c625c2";
    
    public static void main( String[] args ) throws IOException, InterruptedException
    {
    	int choice;
        do {
        	System.out.println("***** Java VirusTotal API *****");
            System.out.println("1. Scan File\n2. Domain Analysis\n3. IP Analysis\n4. URL Analysis");
            System.out.println("*******************************");
            System.out.print("Please choose: ");
            
            @SuppressWarnings("resource")
			Scanner input = new Scanner(System.in);
            if(input.hasNextInt()) {
            	   choice = input.nextInt();
            	   input.nextLine();
            }
            else{
            	System.out.println("ERROR: Invalid Input...\n");
            	continue;
            }
            
            if (choice == 1) {
            	System.out.println("STARTING: File Analysis... ");
            	FileScan fs = new FileScan();
            	UploadFile file = new UploadFile();
            	fs.setFilepath(file.getFile());
                
            	if (fs.isImported()) {
            		fs.POSTFile(true, API_KEY);
            		System.out.println("> File ID: " + fs.getId());
            	} else {
            		System.out.println("ERROR: No file imported!\n");
            		continue;
            	}
                break;

            } else if (choice == 2) {
            	System.out.println("STARTING: Domain Analysis... ");
            	//DomainReport();
            	break;
            } else if (choice == 3) {
            	System.out.println("STARTING: IP Analysis... ");
            	//IPReport();
            	break;
            } else if (choice == 4) {
            	System.out.println("STARTING: URL Analysis... ");
            	//URLReport();
            	break;
            } else
            	System.exit(0);
        } while (true);
    }
}
