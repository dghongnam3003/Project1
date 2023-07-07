package com.hust.cysec.vtapi.object_scan;

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
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.util.CellUtil;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.knowm.xchart.*;
import org.knowm.xchart.style.Styler.*;

public class FileScan extends Scan {
	private String filepath = null;
	private long size = -1;
	private int typeUnsup;
	
	@Override
	public void post (String apikey) throws IOException, InterruptedException {
		if (!isValid())
			return;
    	Path localFile = Paths.get(filepath);
    	String uploadURL = getUploadURL(apikey);
    	
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
	public void getReport(String apikey) throws IOException, InterruptedException {
		if (getObjectId() == null)
			return;
		
		//SEND REANALYSE req if already get report before
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
		
		//GET REPORT req
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
	    	//GET BASIC INFO
	        this.size = json.getJSONObject("data").getJSONObject("attributes").getInt("size");
	        if (getObjectId().matches("[a-fA-F0-9]{40}") || getObjectId().matches("[a-fA-F0-9]{32}"))
	        	setObjectId(json.getJSONObject("data").getString("id"));
	        if (getName() == null)
	        	setName(json.getJSONObject("data").getJSONObject("attributes").getString("meaningful_name"));
	        
	        //GET ANALYSIS 
	        setTime(json.getJSONObject("data").getJSONObject("attributes").getInt("last_analysis_date"));
	        setHarmless(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("harmless"));
	        this.typeUnsup = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("type-unsupported");
	        setSuspicious(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("suspicious"));
	        setTimeout(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("timeout") + json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("confirmed-timeout") + json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("failure"));
	        setMalicious(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("malicious"));
	        setUndetected(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("undetected"));
	    } catch (Exception e) {
			try {
				//check if invalid md5/sha1/sha256 lookup
				if (json.getJSONObject("error").getString("code").equalsIgnoreCase("NotFoundError")) {
					this.setJson(null);
					return;
				}
		        System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
			} catch (Exception ee) {
				//check if analysis not finished
				if (e.getMessage().equals("JSONObject[\"last_analysis_date\"] not found."))
					System.out.println("WARNING: No finished analysis found!");
				else
					System.out.println("ERROR: " + e.getMessage());
			}
	    }
	}

	@Override
	public void printSummary() {
		System.out.println("\n>>> ANALYSIS SUMMARY <<<");
		System.out.println("> Info");
		System.out.println("Name: " + getName());
		if (getObjectId() != null) System.out.println("ID: " + getObjectId());
		if (getTime() == 0) {
			System.out.println("> WARNING: No finished analysis found!\n(Please wait a few seconds and update)");
			return;
		}
		System.out.println("> Analysis stats");
		DateTimeFormatter dateformat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());
		System.out.println("Time: " + dateformat.format(Instant.ofEpochSecond(getTime())));
		System.out.println("Harmless:\t" + getHarmless());
		System.out.println("Undetected:\t" + getUndetected());
		System.out.println("Suspicious:\t" + getSuspicious());
		System.out.println("Malicious:\t" + getMalicious());
		System.out.println("Unsupported:\t" + typeUnsup);
		System.out.println("Timeout:\t" + getTimeout());
	}
	
	@Override
	public void writeExcel(XSSFSheet sheet) {
		if (sheet == null) {
			System.out.println("ERROR: Can't write anything.");
			return;
		}
		
	//WRITE BASIC INFO
		Row row = sheet.getRow(1);
        CellUtil.getCell(row, 0).setCellValue("type");
        CellUtil.getCell(row, 1).setCellValue("id");
        CellUtil.getCell(row, 2).setCellValue("name");
        CellUtil.getCell(row, 9).setCellValue("undetected");
        CellUtil.getCell(row, 10).setCellValue("harmless");
        CellUtil.getCell(row, 11).setCellValue("suspicious");
        CellUtil.getCell(row, 12).setCellValue("malicious");
        CellUtil.getCell(row, 13).setCellValue("type-unsupported");
        CellUtil.getCell(row, 14).setCellValue("timeout");
        CellUtil.getCell(row, 15).setCellValue("last_analysis_date");
        
        row = sheet.getRow(2);
        CellUtil.getCell(row, 0).setCellValue("file");
        CellUtil.getCell(row, 1).setCellValue(getObjectId());
        CellUtil.getCell(row, 2).setCellValue(getName());
        CellUtil.getCell(row, 9).setCellValue(getUndetected());
        CellUtil.getCell(row, 10).setCellValue(getHarmless());
        CellUtil.getCell(row, 11).setCellValue(getSuspicious());
        CellUtil.getCell(row, 12).setCellValue(getMalicious());
        CellUtil.getCell(row, 13).setCellValue(typeUnsup);
        CellUtil.getCell(row, 14).setCellValue(getTimeout());
        CellUtil.getCell(row, 15).setCellValue(getTime());
        
   //WRITE ANALYSIS RESULTS
        row = sheet.getRow(1);
        CellUtil.getCell(row, 16).setCellValue("engine_name");
        CellUtil.getCell(row, 17).setCellValue("category");
        CellUtil.getCell(row, 18).setCellValue("result");
        
        List<JSONObject> engines = new ArrayList<>();
        JSONObject json = getJson().getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_results");
        Iterator<String> keys = json.keys();
        while (keys.hasNext()) {
            JSONObject nestedJsonObject = json.getJSONObject(keys.next());
            engines.add(nestedJsonObject);
        }
        Collections.sort(engines, new Comparator<JSONObject>() {
            @Override
            public int compare(JSONObject j1, JSONObject j2) {
                String name1 = (String) j1.get("engine_name");
                String name2 = (String) j2.get("engine_name");
                return name1.compareToIgnoreCase(name2);
            }
        });
        
        int i_row = 2;
        for (JSONObject engine: engines) {
        	row = sheet.getRow(i_row);
        	if (row == null)
        		row = sheet.createRow(i_row);
        	CellUtil.getCell(row, 16).setCellValue(engine.getString("engine_name"));
            CellUtil.getCell(row, 17).setCellValue(engine.getString("category"));
            try {
            	CellUtil.getCell(row, 18).setCellValue(engine.getString("result"));
            } catch (JSONException e) {}
        	i_row++;
        }
        if (i_row < 101) {
        	row = sheet.getRow(101);
        	CellUtil.getCell(row, 16).setBlank();
        }
        
    // WRITE OTHER FILE INFOS
        row = sheet.getRow(1);
        CellUtil.getCell(row, 3).setCellValue("first_submission_date");
        CellUtil.getCell(row, 4).setCellValue("last_submission_date");
        CellUtil.getCell(row, 5).setCellValue("size");
        CellUtil.getCell(row, 6).setCellValue("type_description");
        CellUtil.getCell(row, 7).setCellValue("type_tags");
        CellUtil.getCell(row, 8).setCellValue("alias");
        CellUtil.getCell(row, 19).setCellValue("reputation");
        CellUtil.getCell(row, 20).setCellValue("harmless");
        CellUtil.getCell(row, 21).setCellValue("malicious");
        CellUtil.getCell(row, 22).setCellValue("magic");
        
        json = getJson().getJSONObject("data").getJSONObject("attributes");
        row = sheet.getRow(2);
        CellUtil.getCell(row, 3).setCellValue(json.getLong("first_submission_date"));
        CellUtil.getCell(row, 4).setCellValue(json.getLong("last_submission_date"));
        CellUtil.getCell(row, 5).setCellValue(size);
        CellUtil.getCell(row, 6).setCellValue(json.getString("type_description"));
        CellUtil.getCell(row, 19).setCellValue(json.getInt("reputation"));
        CellUtil.getCell(row, 20).setCellValue(json.getJSONObject("total_votes").getInt("harmless"));
        CellUtil.getCell(row, 21).setCellValue(json.getJSONObject("total_votes").getInt("malicious"));
        CellUtil.getCell(row, 22).setCellValue(json.getString("magic"));
        //Write File tags
        JSONArray names = json.getJSONArray("type_tags");
        i_row = 2;
        for (int i = 0; i < names.length(); i++) {
        	row = sheet.getRow(i_row);
        	CellUtil.getCell(row, 7).setCellValue(names.getString(i));
        	i_row++;
        }
        //Write File alias
        names = json.getJSONArray("names");
        i_row = 2;
        for (int i = 0; i < names.length(); i++) {
        	row = sheet.getRow(i_row);
        	CellUtil.getCell(row, 8).setCellValue(names.getString(i));
        	i_row++;
        }
	}

	public PieChart toChart() throws IOException {
		if (getTime() == 0) {
			System.out.println("WARNING: No finished analysis found!\n(Please wait a few seconds and update)");
			return null;
		}
		// Create Chart
		DateTimeFormatter dateformat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());
		String short_time = dateformat.format(Instant.ofEpochSecond(getTime()));
	    PieChart chart = new PieChartBuilder().width(800).height(600).title(getName() + " ("+short_time+")").theme(ChartTheme.GGPlot2).build();

	    // Customize Chart
	    chart.getStyler().setLegendVisible(false);
//	    chart.getStyler().setAnnotationType(AnnotationType.LabelAndPercentage);
//	    chart.getStyler().setAnnotationDistance(1.15);
	    chart.getStyler().setPlotContentSize(.7);
	    chart.getStyler().setStartAngleInDegrees(90);

	    // Series
	    chart.addSeries("harmless", getHarmless());
	    chart.addSeries("undetected", getUndetected());
	    chart.addSeries("suspicious", getSuspicious());
	    chart.addSeries("malicious", getMalicious());
	    chart.addSeries("timeout", getTimeout());
	    chart.addSeries("type-unsupported", typeUnsup);
	    
		return chart;
	}

	private String getUploadURL(String apikey) throws IOException, InterruptedException {
		//Get a URL for uploading files larger than 32MB
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
	
	@Override
	public boolean isValid() {
		if(this.filepath == null) {
			return false;
		} else {
			return true;
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
				this.setName(file.getName());
			} catch (IOException e) {
				this.filepath = null;
			}
		}
	}
	public long getSize() {
		return size;
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