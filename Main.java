import java.util.Scanner;
 
public class Main {
 
    public static void main(String[] args) {
 
        Scanner keyboard = new Scanner(System.in); // for reading user input
 
        System.out.println("========== PHISHING EMAIL DETECTOR ==========");
 
        // get email subject from user
        System.out.print("Enter email subject: ");
        String subject = keyboard.nextLine();
 
        // get email body from user - keeps reading lines until the user types END
        // (before this, only the first line of the body was read)
        System.out.println("Enter email body (type END on a new line when finished):");
        StringBuilder bodyBuilder = new StringBuilder();
        while (keyboard.hasNextLine()) {
            String line = keyboard.nextLine();
            if (line.trim().equalsIgnoreCase("END")) {
                break; // user is done typing the body
            }
            bodyBuilder.append(line).append("\n");
        }
        String body = bodyBuilder.toString();
 
        // create EmailScanner object and scan the email
        EmailScanner scanner = new EmailScanner(subject, body);
        scanner.scanKeywords();         // check for suspicious keywords
        scanner.scanDomains();          // check for known suspicious domains
        scanner.scanLookalikeDomains(); // check for fake brand domains like paypa1.com
        scanner.scanLinks();            // check links for http, raw IPs and shorteners
 
        // get results from scanner
        String riskLevel = scanner.getRiskLevelResult();
 
        // create ReportGenerator object and print the report
        ReportGenerator report = new ReportGenerator(riskLevel,
                scanner.getMatchedKeywords(),
                scanner.getMatchedDomains(),
                scanner.getLookalikeWarnings(),
                scanner.getLinkWarnings());
        report.printReport();
 
        keyboard.close();
    }
}