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

public class FileScan extends Scan {
	private String filepath = null;
	private long size = -1;
	private String sha1 = null;
	private String md5 = null;
	private int typeUnsup;
	private int failure;
	
	@Override
	public void POST (String apikey) throws IOException, InterruptedException {
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
        
        //UPDATE AnalysisId
        try {
	        this.setAnalysisId(json.getJSONObject("data").getString("id"));
        } catch (Exception e) {
			try {
		        System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
			} catch (Exception ee) {
				System.out.println("ERROR: " + e.getMessage());
			}
	    }
        
        // UPDATE ObjectId
        if (this.getObjectId() == null) {
			if (this.getAnalysisId() != null) {
				HttpRequest req = HttpRequest.newBuilder()
					    .uri(URI.create("https://www.virustotal.com/api/v3/analyses/" + getAnalysisId()))
					    .header("accept", "application/json")
					    .header("x-apikey", apikey)
					    .method("GET", HttpRequest.BodyPublishers.noBody())
					    .build();
					HttpResponse<String> resp = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
				JSONObject temp = new JSONObject(resp.body());
				try {
			        this.setObjectId(temp.getJSONObject("meta").getJSONObject("file_info").getString("sha256"));
				} catch (Exception e) {
					try {
				        System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
					} catch (Exception ee) {
						System.out.println("ERROR: " + e.getMessage());
					}
			    }
			}
		}
	}
	
	@Override
	public void GETReport(String apikey) throws IOException, InterruptedException {
		if (getObjectId() == null)
			return;
		
		//REANALYSE if already get report before
		if (getJson() != null) { 
			HttpRequest rescan = HttpRequest.newBuilder()
				    .uri(URI.create("https://www.virustotal.com/api/v3/files/" + getObjectId() + "/analyse"))
				    .header("accept", "application/json")
				    .header("x-apikey", apikey)
				    .method("POST", HttpRequest.BodyPublishers.noBody())
				    .build();
				HttpResponse<String> resp = HttpClient.newHttpClient().send(rescan, HttpResponse.BodyHandlers.ofString());
				JSONObject temp = new JSONObject(resp.body());
			try {
		        this.setAnalysisId(temp.getJSONObject("data").getString("id"));
			} catch (Exception e) {
				try {
			        System.out.println("ERROR: " + temp.getJSONObject("error").getString("message") + " (" + temp.getJSONObject("error").getString("code") + ")");
				} catch (Exception ee) {
					System.out.println("ERROR: " + e.getMessage());
				}
		    }
		}
		
		HttpRequest request = HttpRequest.newBuilder()
			    .uri(URI.create("https://www.virustotal.com/api/v3/files/" + this.getObjectId()))
			    .header("accept", "application/json")
			    .header("x-apikey", apikey)
			    .method("GET", HttpRequest.BodyPublishers.noBody())
			    .build();
			HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
		JSONObject json = new JSONObject(response.body());
		this.setJson(json);
		
	    try {
	        this.sha1 = json.getJSONObject("data").getJSONObject("attributes").getString("sha1");
	        this.md5 = json.getJSONObject("data").getJSONObject("attributes").getString("md5");
	        this.size = json.getJSONObject("data").getJSONObject("attributes").getInt("size");
	        setHarmless(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("harmless"));
	        this.typeUnsup = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("type-unsupported");
	        setSuspicious(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("suspicious"));
	        setTimeout(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("timeout"));
	        this.failure = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("failure");
	        setMalicious(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("malicious"));
	        setUndetected(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("undetected"));
	        setTime(json.getJSONObject("data").getJSONObject("attributes").getInt("last_analysis_date"));
	        
	        printSummary();
	    } catch (Exception e) {
			try {
		        System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
			} catch (Exception ee) {
				System.out.println("ERROR: " + e.getMessage());
			}
	    }
	}

	@Override
	public void toCSVReport() {
		if (this.getObjectId() == null || this.getJson() == null ) {
			return;
		}
		String filename = ("FILE_REPORT_" + getName().replaceAll("[^\\dA-Za-z ]", "").replaceAll("\\s+", "_") + "_" + getTime() + ".json");
		boolean isNewFile = !new File("file_report.csv").exists();
		try (FileWriter writer = new FileWriter("file_report.csv", true)) {
	        // Write header
			if (isNewFile) {
				writer.write("Name,Size,SHA256,SHA1,MD5,Harmless,Suspicious,Malicious,Undetected,Unsupported,Timeout,Failure\n");
			}
	
	        // Write CSV
	        StringBuilder sb = new StringBuilder();
	        sb.append(getName().replace(",", "")).append(",")
	                .append(size).append(",")
	                .append(getObjectId()).append(",")
	                .append(sha1).append(",")
	                .append(md5).append(",")
	                .append(getHarmless()).append(",")
	                .append(getSuspicious()).append(",")
	                .append(getMalicious()).append(",")
	                .append(getUndetected()).append(",")
	                .append(typeUnsup).append(",")
	                .append(getTimeout()).append(",")
	                .append(failure).append("\n");
	
	        writer.write(sb.toString());
	    } catch (IOException e) {
	        System.out.printf("ERROR: Failed to write CSV file (%s)\n",e.getMessage());
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
        } catch (Exception e) {
			try {
		        System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
			} catch (Exception ee) {
				System.out.println("ERROR: " + e.getMessage());
			}
	    }
		return null;
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
				this.setName(file.getName());
			} catch (IOException e) {
				this.filepath = null;
			}
		}
	}
	
	public long getSize() {
		return size;
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