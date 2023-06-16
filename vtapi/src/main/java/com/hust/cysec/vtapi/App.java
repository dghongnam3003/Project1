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
            System.out.println("1. File Scan\n2. URL Scan\n3. Domain Analysis\n4. IP Analysis\n0. Exit");
            System.out.println("*******************************");
            System.out.print("> Please choose: ");
            
            @SuppressWarnings("resource")
			Scanner input = new Scanner(System.in);
            if(input.hasNextInt()) {
            	   choice = input.nextInt();
            	   input.nextLine();
            }
            else {
            	System.out.println("ERROR: Invalid Input...\n");
            	Thread.sleep(1000);
            	continue;
            }
            
            switch (choice) {
            	case 1:
	            	System.out.println("STARTING: File Analysis");
	            	System.out.println("\n>>> CHOOSE FILE <<<");
	            	System.out.println("Press ENTER to Browse Files...");
	            	System.out.print("Or Input filename (in this directory): ");
	            	String filename = input.nextLine().strip();
	            	FileScan fs = new FileScan();
	            	if (filename.isBlank()) {
	                	UploadFile file = new UploadFile();
	                	fs.setFilepath(file.getFile());
	            	} else {
	            		File file = new File(filename);
	            		fs.setFilepath(file);
	            	}
	                
	            	if (fs.isImported()) {
	            		System.out.println("...Posting");
	            		fs.POST(API_KEY);
	            	} else {
	            		System.out.println("ERROR: No file imported!\n");
	            		Thread.sleep(1000);
	            		break;
	            	}
	            	
	            	System.out.println("...Getting report");
            		fs.GETReport(API_KEY);
            		System.out.println("...Saving");
            		fs.toCSVReport();
            		Thread.sleep(1000);
	                break;

            	case 2:
            		System.out.println("STARTING: URL Analysis");
                	System.out.print("Input URL (or press Enter to cancel): ");
                	String url = input.nextLine().strip();
                	System.out.println("");
                	URLScan us = new URLScan();
                	if (!url.isBlank()) {
    	            	us.setName(url);
    	            	System.out.println("...Posting");
    	            	us.POST(API_KEY);
                	} else{
                    	System.out.println("ERROR: Invalid Input...\n");
                    	Thread.sleep(1000);
                    	break;
                    }
                	
                	System.out.println("...Getting report");
	            	us.GETReport(API_KEY);
	            	System.out.println("...Saving");
	            	us.toCSVReport();
                	
                	Thread.sleep(1000);
                	break;
            	case 3:
	            	System.out.println("STARTING: IP Analysis");
	            	System.out.println("STARTING: IP Analysis");
	            	System.out.print("Input IP (or press Enter to cancel): ");
	            	String ip = input.nextLine().strip();
	            	IPScan ipScan = new IPScan();
	            	
	            	if (ipScan.isValisIP(ip) ) {
	            		System.out.println("...Getting report");
		            	ipScan.GETReport(API_KEY, ip);
		            	System.out.println("...Saving");
		            	ipScan.toCSVReport();
	            	} else{
	                	System.out.println("ERROR: Invalid Input...\n");
	                	Thread.sleep(2000);
	                	continue;
	                }
	            	break;
            	case 4:
	            	System.out.println("STARTING: Domain Analysis");
	            	//DomainReport();
	            	break;
            	case 0:
            		System.exit(0);
            	default:
            		System.out.println("ERROR: Invalid Input...\n");
                	Thread.sleep(1000);
            }
        } while (true);
    }
}