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
        	System.out.println("***** JAVA VIRUSTOTAL API *****");
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
	            		System.out.println("...Uploading & Scanning");
	            		fs.POST(API_KEY);
	            	} else {
	            		System.out.println("ERROR: No file imported!\n");
	            		Thread.sleep(1000);
	            		break;
	            	}

	            	System.out.println("...Getting report");
            		fs.GETReport(API_KEY);
            		
            		actionsMenu(fs, input);
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
    	            	System.out.println("...Scanning");
    	            	us.POST(API_KEY);
                	} else{
                    	System.out.println("ERROR: Invalid Input...\n");
                    	Thread.sleep(1000);
                    	break;
                    }
                	
                	System.out.println("...Getting report");
	            	us.GETReport(API_KEY);
	            	
	            	actionsMenu(us, input);
                	Thread.sleep(1000);
                	break;
            	case 3:
            		System.out.println("STARTING: Domain Analysis");
	            	System.out.print("Input Domain (or press Enter to cancel): ");
	            	String domain = input.nextLine().strip();
	            	DomainScan ds = new DomainScan();
	            	
	            	if (ds.isValidDomain(domain) ) {
	            		System.out.println("...Getting report");
		            	ds.GETReport(API_KEY, domain);
		            	System.out.println("...Saving");
		            	ds.toCSVReport();
	            	} else{
	                	System.out.println("ERROR: Invalid Input...\n");
	                	Thread.sleep(2000);
	                	continue;
	                }
	            	break;
            	case 4:
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
            	case 0:
            		System.out.println("Good bye!");
            		System.exit(0);
            	default:
            		System.out.println("ERROR: Invalid Input...\n");
                	Thread.sleep(1000);
                	break;
            }
        } while (true);
    }
    
    public static void actionsMenu (Scan ss, Scanner keyboard) throws InterruptedException, IOException {
    	int choice = -1;
    	String extra = "";
		if (ss instanceof FileScan || ss instanceof URLScan)
			extra = "\n4. Re-analysis File/URL";
    	do {
    		Thread.sleep(1000);
    		System.out.println("\n*** OPTIONS ***");
            System.out.println("1. Save Report to JSON\n2. Save Report to CSV\n3. Display Report summary" + extra +"\n0. Exit to Main menu");
            System.out.println("***************");
            System.out.print("> Please choose: ");
    		
    		if(keyboard.hasNextInt()) {
    			choice = keyboard.nextInt();
         	   	keyboard.nextLine();
    		}
            else {
             	System.out.println("ERROR: Invalid Input...\n");
             	continue;
             }
    		
    		switch (choice) {
    		case 1:
    			System.out.println("...Saving to JSON...");
    			ss.toJSONReport();
    			System.out.println("...Saved!");
    			break;
    		case 2:
    			System.out.println("...Saving to CSV...");
    			ss.toCSVReport();
    			System.out.println("...Saved!");
    			break;
    		case 3:
    			ss.printSummary();
    			break;
    		case 0:
    			System.out.println("\n\n");
    			return;
    		case 4:
    			if (ss instanceof FileScan || ss instanceof URLScan) {
    				ss.GETReport(API_KEY);
        			break;
    			}
    		default:
    			System.out.println("ERROR: Invalid Input...\n");
             	continue;
    		}
    	} while (true);
    }
}