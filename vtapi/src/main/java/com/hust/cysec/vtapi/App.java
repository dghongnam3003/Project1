package com.hust.cysec.vtapi;

import java.util.*;
import java.net.*;
import java.io.File;

public class App 
{
    private final static String API_Report = "https://www.virustotal.com/vtapi/v2/file/report?";
    private final static String API_Scan = "https://www.virustotal.com/vtapi/v2/file/scan";
    private final static String API_KEY = "ffefe1cf95c72be26918974d944179629816e48e7590c64f484b43dbc2c625c2";
    public static File file;
    
    public static void main( String[] args )
    {
    	int choice;
        @SuppressWarnings("resource")
		Scanner in = new Scanner(System.in);
        do {
        	System.out.println("***** Java VirusTotal API *****");
            System.out.println("1. Scan File\n2. Domain Analysis\n3. IP Analysis\n4. URL Analysis");
            System.out.println("*******************************");
            System.out.print("Please choose: ");
            try {
            	choice = in.nextInt();
                if (choice == 1) {
                	System.out.println("Starting File Analysis... ");
                	//FileReport();
                    break;
                } else if (choice == 2) {
                	System.out.println("Starting Domain Analysis... ");
                	//DomainReport();
                	break;
                } else if (choice == 3) {
                	System.out.println("Starting IP Analysis... ");
                	//IPReport();
                	break;
                } else if (choice == 4) {
                	System.out.println("Starting URL Analysis... ");
                	//URLReport();
                	break;
                } else
                	System.exit(0);
            } catch (InputMismatchException e)
            	{System.exit(0);}
        } while (true);
        
    }
}
