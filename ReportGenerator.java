import java.util.ArrayList;
import java.util.Random;
 
public class ReportGenerator {
 
    // private fields
    private String reportID;
    private String riskLevel;
    private ArrayList<String> matchedKeywords;
    private ArrayList<String> matchedDomains;
    private ArrayList<String> lookalikeWarnings;
    private ArrayList<String> linkWarnings;
 
    // constructor - takes results from EmailScanner
    public ReportGenerator(String riskLevel, ArrayList<String> matchedKeywords, ArrayList<String> matchedDomains,
                           ArrayList<String> lookalikeWarnings, ArrayList<String> linkWarnings) {
        this.riskLevel = riskLevel;
        this.matchedKeywords = matchedKeywords; // priv field blongs to class
        this.matchedDomains = matchedDomains;
        this.lookalikeWarnings = lookalikeWarnings;
        this.linkWarnings = linkWarnings;
        this.reportID = generateReportID(); // generate ID when object is created
    }
 
    // generates a random report ID using Random class
    private String generateReportID() {
        Random rand = new Random();
        int id = rand.nextInt(90000) + 10000; // gives a random 5 digit number
        return "RPT-" + id;
    }
 
    // prints one section of the report - saves repeating the same loop four times
    private void printSection(String title, ArrayList<String> items) {
        System.out.println("\n" + title + ":");
        if (items.size() == 0) {
            System.out.println("  None");
        } else {
            for (int i = 0; i < items.size(); i++) {
                System.out.println("  - " + items.get(i)); // how u access an element in an ArrayList
            }
        }
    }
 
    // prints the full threat report to the console
    public void printReport() {
        int total = matchedKeywords.size() + matchedDomains.size() + lookalikeWarnings.size() + linkWarnings.size();
 
        System.out.println("\n========== PHISHING THREAT REPORT ==========");
        System.out.println("Report ID    : " + reportID);
        System.out.println("Risk Level   : " + riskLevel);
        System.out.println("Total Flags  : " + total);
 
        printSection("Suspicious Keywords Detected", matchedKeywords);
        printSection("Known Suspicious Domains Detected", matchedDomains);
        printSection("Lookalike Domains Detected", lookalikeWarnings);
        printSection("Risky Links Detected", linkWarnings);
 
        // recommendation based on risk level
        System.out.println("\nRecommendation:");
        if (riskLevel.equals("HIGH")) {
            System.out.println("  Do NOT click any links. Report this email immediately.");
        } else if (riskLevel.equals("MEDIUM")) {
            System.out.println("  Be cautious. Verify the sender before taking any action.");
        } else {
            System.out.println("  Email appears safe but always stay alert.");
        }
 
        System.out.println("============================================");
    }
}
 