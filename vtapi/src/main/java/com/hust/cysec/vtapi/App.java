package com.hust.cysec.vtapi;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class App 
{
    private final static String API_URL = "https://www.virustotal.com/api/v3";
    private final static String API_KEY = "ffefe1cf95c72be26918974d944179629816e48e7590c64f484b43dbc2c625c2";
    
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
            	System.out.println("Invalid Input...\n");
            	continue;
            }
            
            if (choice == 1) {
            	System.out.println("Starting File Analysis... ");
            	//System.out.print("Choose file: ");
            	//String filename = input.nextLine().strip();
            	//System.out.printf("\nFile: %s", filename);
            	FileScan fs = new FileScan();
            	UploadFile file = new UploadFile();
            	fs.setFilepath(file.getFile());
            	Path localFile = Paths.get(fs.getFilepath());
            	
            	HttpClient client = HttpClient.newBuilder().build();

                Map<Object, Object> data = new LinkedHashMap<>();
                data.put("file", localFile);
                String boundary = "---011000010111000001101001";

                HttpRequest request = HttpRequest.newBuilder()
                    .header("Content-Type", "multipart/form-data;boundary=" + boundary)
                    .header("x-apikey", API_KEY).POST(ofMimeMultipartData(data, boundary))
                    .uri(URI.create(API_URL + "/files")).build();

                HttpResponse<String> vtResponse = client.send(request, BodyHandlers.ofString());
                System.out.println(vtResponse.body());
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
        } while (true);
        
    }
    public static BodyPublisher ofMimeMultipartData(Map<Object, Object> data,
    	      String boundary) throws IOException {
    	    var byteArrays = new ArrayList<byte[]>();
    	    byte[] separator = ("--" + boundary + "\r\nContent-Disposition: form-data; name=")
    	        .getBytes(StandardCharsets.UTF_8);
    	    for (Map.Entry<Object, Object> entry : data.entrySet()) {
    	      byteArrays.add(separator);

    	      if (entry.getValue() instanceof Path) {
    	        var path = (Path) entry.getValue();
    	        String mimeType = Files.probeContentType(path);
    	        byteArrays.add(("\"" + entry.getKey() + "\"; filename=\"" + path.getFileName()
    	            + "\"\r\nContent-Type: " + mimeType + "\r\n\r\n")
    	                .getBytes(StandardCharsets.UTF_8));
    	        byteArrays.add(Files.readAllBytes(path));
    	        byteArrays.add("\r\n".getBytes(StandardCharsets.UTF_8));
    	      }
    	      else {
    	        byteArrays.add(("\"" + entry.getKey() + "\"\r\n\r\n" + entry.getValue() + "\r\n")
    	            .getBytes(StandardCharsets.UTF_8));
    	      }
    	    }
    	    byteArrays.add(("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
    	    return BodyPublishers.ofByteArrays(byteArrays);
    	  }
}
