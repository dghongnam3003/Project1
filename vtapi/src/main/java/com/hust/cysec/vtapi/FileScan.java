package com.hust.cysec.vtapi;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONObject;

public class FileScan {
	private String filepath = null;
	private String id = null;
	private String sha256 = null;
	private String sha1 = null;
	private String md5 = null;
	private int size = -1;

	public String getFilepath() {
		return filepath;
	}

	public void setFilepath(File file) {
		if(file == null) {
			this.filepath = null;
		} else {
			this.filepath = file.getAbsolutePath();
		}
	}
	
	public String getId() {
		return id;
	}

	public boolean isImported() {
		if(this.filepath == null) {
			return false;
		} else {
			return true;
		}
	}
	
	public void POSTFile(boolean fullupload, String apikey) throws IOException, InterruptedException {
		// UPDATE FILESCAN ID
		if (fullupload) {
			if (!isImported())
				return;
	    	Path localFile = Paths.get(filepath);
	    	
	    	HttpClient client = HttpClient.newBuilder().build();

	        Map<Object, Object> data = new LinkedHashMap<>();
	        data.put("file", localFile);
	        String boundary = "---011000010111000001101001";

	        HttpRequest request = HttpRequest.newBuilder()
	            .header("Content-Type", "multipart/form-data;boundary=" + boundary)
	            .header("x-apikey", apikey).POST(ofMimeMultipartData(data, boundary))
	            .uri(URI.create("https://www.virustotal.com/api/v3/files")).build();

	        HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
	        JSONObject json = new JSONObject(response.body());
	        try {
		        String id = json.getJSONObject("data").getString("id");
		        this.id = id;
	        } catch (org.json.JSONException e) {
		        System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
		        return;
	        }
		}
	}
	
	public void GETReport(String apikey) throws IOException, InterruptedException {
		if (this.id == null) {
			return;
		}
		HttpRequest request = HttpRequest.newBuilder()
			    .uri(URI.create("https://www.virustotal.com/api/v3/analyses/"+this.id))
			    .header("accept", "application/json")
			    .header("x-apikey", apikey)
			    .method("GET", HttpRequest.BodyPublishers.noBody())
			    .build();
			HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
		JSONObject json = new JSONObject(response.body());
        try {
	        this.sha256 = json.getJSONObject("meta").getJSONObject("file_info").getString("sha256");
	        this.sha1 = json.getJSONObject("meta").getJSONObject("file_info").getString("sha1");
	        this.md5 = json.getJSONObject("meta").getJSONObject("file_info").getString("md5");
	        this.size = json.getJSONObject("meta").getJSONObject("file_info").getInt("size");
        } catch (org.json.JSONException e) {
	        System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
	        return;
        }
	}
	
	public void printReport() {
		System.out.println(">>> FILE REPORT SUMMARY <<<");
		if (this.id == null || this.sha256 == null) {
			System.out.println("ERROR: No report found...");
			return;
		}
		System.out.println("> Metadata");
		System.out.println("File size: " + size + " bytes");
		System.out.println("SHA256: " + sha256);
		System.out.println("SHA1: " + sha1);
		System.out.println("MD5: " + md5);
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
