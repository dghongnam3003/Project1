package com.hust.cysec.vtapi;
// mvn clean compile assembly:single

import java.io.IOException;
import java.util.*;
import java.io.File;

public class App 
{
    public final static String API_KEY = "740bce69a223d9434f8c789ce8b432e3e15cbfb4e8bf78b72a6fa41396b8b53a";
    
    public static void main( String[] args ) throws IOException, InterruptedException
    {
    	int choice;
        do {
        	System.out.println("***** Java VirusTotal API *****");
            System.out.println("1. Scan File\n2. Domain Analysis\n3. IP Analysis\n4. URL Analysis");
            System.out.println("*******************************");
            System.out.print("> Please choose: ");
            
            @SuppressWarnings("resource")
			Scanner input = new Scanner(System.in);
            if(input.hasNextInt()) {
            	   choice = input.nextInt();
            	   input.nextLine();
            }
            else{
            	System.out.println("ERROR: Invalid Input...\n");
            	Thread.sleep(2000);
            	continue;
            }
            
            if (choice == 1) {
            	System.out.println("STARTING: File Analysis");
            	System.out.println("\n>>> CHOOSE FILE <<<");
            	System.out.println("Press ENTER to Browse Files...");
            	System.out.print("Or Input filename (in this directory): ");
            	String filename = input.nextLine().strip();
            	FileScan fs = new FileScan();
            	if (filename.isEmpty()) {
                	UploadFile file = new UploadFile();
                	fs.setFilepath(file.getFile());
            	} else {
            		File file = new File(filename);
            		fs.setFilepath(file);
            	}
                
            	if (fs.isImported()) {
            		fs.POSTFile(true, API_KEY);
            		System.out.println("> Report ID: " + fs.getId());
            		fs.GETReport(API_KEY);
            		fs.printReport();
            	} else {
            		System.out.println("ERROR: No file imported!\n");
            		Thread.sleep(2000);
            		continue;
            	}
                break;

            } else if (choice == 2) {
            	System.out.println("STARTING: Domain Analysis");
            	//DomainReport();
            	break;
            } else if (choice == 3) {
            	System.out.println("STARTING: IP Analysis");
            	//IPReport();
            	break;
            } else if (choice == 4) {
            	System.out.println("STARTING: URL Analysis");
            	//URLReport();
            	break;
            } else
            	System.exit(0);
        } while (true);
        System.exit(0);
    }
}