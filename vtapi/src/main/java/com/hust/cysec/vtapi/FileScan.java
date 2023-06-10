package com.hust.cysec.vtapi;

import java.io.FileWriter;
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
	private long size = -1;
	private String name = null;
	private String id = null;
	private String sha256 = null;
	private String sha1 = null;
	private String md5 = null;
	private int harmless;
	private int typeUnsup;
	private int suspicious;
	private int confirmedTimeOut;
	private int timeOut;
	private int failure;
	private int malicious;
	private int undetected;
	
	public void POSTFile(boolean fullupload, String apikey) throws IOException, InterruptedException {
		// UPDATE FILESCAN ID
		if (fullupload) {
			if (!isImported())
				return;
	    	Path localFile = Paths.get(filepath);
	    	String uploadURL = GETUploadURL(apikey);
	    	
	    	HttpClient client = HttpClient.newBuilder().build();

	        Map<Object, Object> data = new LinkedHashMap<>();
	        data.put("file", localFile);
	        String boundary = "---011000010111000001101001";

	        HttpRequest request = HttpRequest.newBuilder()
	            .header("Content-Type", "multipart/form-data;boundary=" + boundary)
	            .header("x-apikey", apikey).POST(ofMimeMultipartData(data, boundary))
	            .uri(URI.create(uploadURL)).build();

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
	
	//Get a URL for uploading files larger than 32MB
	private String GETUploadURL(String apikey) throws IOException, InterruptedException {
		if(this.size < 33554432) {
			return "https://www.virustotal.com/api/v3/files";
		}
		
		HttpRequest request = HttpRequest.newBuilder()
			    .uri(URI.create("https://www.virustotal.com/api/v3/files/upload_url"))
			    .header("accept", "application/json")
			    .header("x-apikey", apikey)
			    .method("GET", HttpRequest.BodyPublishers.noBody())
			    .build();
		HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
		JSONObject json = new JSONObject(response.body());
        try {
	        String url = json.getString("data");
	        System.out.println("(Warning: Uploading file >32MB)");
	        return url;
        } catch (org.json.JSONException e) {
	        System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
	        return "";
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
	        this.harmless = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("harmless");
	        this.typeUnsup = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("type-unsupported");
	        this.suspicious = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("suspicious");
	        this.confirmedTimeOut = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("confirmed-timeout");
	        this.timeOut = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("timeout");
	        this.failure = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("failure");
	        this.malicious = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("malicious");
	        this.undetected = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("undetected");
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
		System.out.println("File name: " + name);
		System.out.println("File size: " + size + " bytes");
		System.out.println("SHA256: " + sha256);
		System.out.println("SHA1: " + sha1);
		System.out.println("MD5: " + md5);
		System.out.println("> Stats");
		System.out.println("Harmless: " + harmless);
		System.out.println("Unsupported types: " + typeUnsup);
		System.out.println("Suspicious: " + suspicious);
		System.out.println("Confirmed timeout: " + confirmedTimeOut);
		System.out.println("Timeout: " + timeOut);
		System.out.println("Failure: " + failure);
		System.out.println("Malicious: " + malicious);
		System.out.println("Undetected: " + undetected);
		
		boolean isNewFile = !new File("report.csv").exists();
		try (FileWriter writer = new FileWriter("report.csv", true)) {
	        // Write header
			if (isNewFile) {
				writer.write("File name,File size (byte),SHA256,SHA1,MD5,Harmless,Unsupported types,Suspicious,Confirmed timeout,Timeout,Failure,Malicious,Undetected\n");
			}

	        // Write data
	        StringBuilder sb = new StringBuilder();
	        sb.append(name).append(",")
	                .append(size).append(",")
	                .append(sha256).append(",")
	                .append(sha1).append(",")
	                .append(md5).append(",")
	                .append(harmless).append(",")
	                .append(typeUnsup).append(",")
	                .append(suspicious).append(",")
	                .append(confirmedTimeOut).append(",")
	                .append(timeOut).append(",")
	                .append(failure).append(",")
	                .append(malicious).append(",")
	                .append(undetected).append("\n");

	        writer.write(sb.toString());
	    } catch (IOException e) {
	        System.out.println("ERROR: Failed to write CSV file: " + e.getMessage());
	    }
	}
	
	public String getFilepath() {
		return filepath;
	}
	public void setFilepath(File file) {
		if(file == null) {
			this.filepath = null;
		} else {
			this.filepath = file.getAbsolutePath();
			try {
				this.size = Files.size(Paths.get(filepath));
				this.name = file.getName();
			} catch (IOException e) {
				this.filepath = null;
			}
		}
	}
	
	public String getId() {
		return id;
	}
	public long getSize() {
		return size;
	}
	public String getName() {
		return name;
	}
	public String getSha256() {
		return sha256;
	}
	public String getSha1() {
		return sha1;
	}
	public String getMd5() {
		return md5;
	}

	public boolean isImported() {
		if(this.filepath == null) {
			return false;
		} else {
			return true;
		}
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