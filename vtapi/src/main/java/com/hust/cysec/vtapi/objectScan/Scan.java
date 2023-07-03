package com.hust.cysec.vtapi.objectScan;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import org.json.JSONObject;
import org.knowm.xchart.*;
import org.knowm.xchart.style.Styler.*;

public abstract class Scan {
	private String name = null;
	private String objectId = null;
	private String analysisId = null;
	private int harmless =0;
	private int suspicious =0;
	private int timeout =0;
	private int malicious =0;
	private int undetected =0;
	private long time = 0;
	private JSONObject json = null;
	
	public void post(String apikey) throws IOException, InterruptedException {
		//POST info and save report IDs
		objectId = null;
		analysisId = null;
	}
	
	public void getReport(String apikey) throws IOException, InterruptedException {
		//GET json report and save json + summary stats
		json = null;
		harmless = 0;
		suspicious = 0;
		timeout = 0;
		malicious = 0;
		undetected = 0;
		time = 0;
	}
	
	public void printSummary() {
		System.out.println("\n>>> ANALYSIS SUMMARY <<<");
		System.out.println("> Info");
		System.out.println("Name: " + name);
		if (objectId != null) System.out.println("ID: " + objectId);
		if (getTime() == 0) {
			System.out.println("> WARNING: No finished analysis found!\n(Please wait a few seconds and update)");
			return;
		}
		System.out.println("> Analysis Stats");
		DateTimeFormatter dateformat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());
		System.out.println("Time: " + dateformat.format(Instant.ofEpochSecond(time)));
		System.out.println("Harmless:\t" + harmless);
		System.out.println("Undetected:\t" + undetected);
		System.out.println("Suspicious:\t" + suspicious);
		System.out.println("Malicious:\t" + malicious);
		System.out.println("Timeout:\t" + timeout);
	}
	
	public boolean toJsonReport() {
		json = getJson();
		if (json == null) {
			System.out.println("ERROR: No report found...");
			return false;
		}
		try (FileWriter writer = new FileWriter(genSaveName("report", ".json"))) {
			writer.write(getJson().toString(4));
			return true;
		} catch (Exception e) {
			try {
		        System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
			} catch (Exception ee) {
				System.out.println("ERROR: " + e.getMessage());
			}
	    }
		return false;
	}
	
	public void toExcelReport() {
		if (this.getObjectId() == null || getJson() == null) {
			System.out.println("ERROR: No report found...");
			return;
		}
	}
	
	public PieChart toChart() throws IOException {
		if (getTime() == 0) {
			System.out.println("WARNING: No finished analysis found!\n(Please wait a few seconds and update)");
			return null;
		}
		// Create Chart
		DateTimeFormatter dateformat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());
		String short_time = dateformat.format(Instant.ofEpochSecond(time));
	    PieChart chart = new PieChartBuilder().width(800).height(600).title(this.name + " ("+short_time+")").theme(ChartTheme.GGPlot2).build();

	    // Customize Chart
	    chart.getStyler().setLegendVisible(false);
//	    chart.getStyler().setAnnotationType(AnnotationType.LabelAndPercentage);
//	    chart.getStyler().setAnnotationDistance(1.15);
	    chart.getStyler().setPlotContentSize(.7);
	    chart.getStyler().setStartAngleInDegrees(90);

	    // Series
	    chart.addSeries("harmless", this.harmless);
	    chart.addSeries("undetected", this.undetected);
	    chart.addSeries("suspicious", this.suspicious);
	    chart.addSeries("malicious", malicious);
	    chart.addSeries("timeout", this.timeout);
	    
		return chart;
	}
	
	
	public boolean isValid() {
		if (this.name == null)
			return false;
		return true;
	}
	
	public String genSaveName(String type) {
		DateTimeFormatter dateformat = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm").withZone(ZoneId.systemDefault());
		String short_time = dateformat.format(Instant.ofEpochSecond(time));
		String savename = type.toUpperCase() + "_" + name.replace("://", "-").replace(".", "-").replaceAll("[^\\dA-Za-z ]", "").replaceAll("\\s+", "-") + "_" + short_time;
		return savename;
	}
	
	public String genSaveName(String type, String extension) {
		DateTimeFormatter dateformat = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm").withZone(ZoneId.systemDefault());
		String short_time = dateformat.format(Instant.ofEpochSecond(time));
		String savename = type.toUpperCase() + "_" + name.replace("://", "-").replace(".", "-").replaceAll("[^\\dA-Za-z ]", "").replaceAll("\\s+", "-") + "_" + short_time + extension;
		return savename;
	}
	
	
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getObjectId() {
		return objectId;
	}
	public void setObjectId(String id) {
		this.objectId = id;
	}
	public int getHarmless() {
		return harmless;
	}
	public void setHarmless(int harmless) {
		this.harmless = harmless;
	}
	public int getSuspicious() {
		return suspicious;
	}
	public void setSuspicious(int suspicious) {
		this.suspicious = suspicious;
	}
	public int getTimeout() {
		return timeout;
	}
	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}
	public int getMalicious() {
		return malicious;
	}
	public void setMalicious(int malicious) {
		this.malicious = malicious;
	}
	public int getUndetected() {
		return undetected;
	}
	public void setUndetected(int undetected) {
		this.undetected = undetected;
	}
	public JSONObject getJson() {
		return json;
	}
	public void setJson(JSONObject json) {
		this.json = json;
	}
	public long getTime() {
		return time;
	}
	public void setTime(int time) {
		this.time = time;
	}
	public String getAnalysisId() {
		return analysisId;
	}
	public void setAnalysisId(String analysisId) {
		this.analysisId = analysisId;
	}
}
