import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
 
public class EmailScanner {
 
    // private fields - other classes cant touch these directly
    private String emailSubject;
    private String emailBody;
    private ArrayList<String> matchedKeywords;
    private ArrayList<String> matchedDomains;
    private ArrayList<String> lookalikeWarnings;
    private ArrayList<String> linkWarnings;
    private ThreatDatabase database;
 
    // patterns used to find domains and links inside the email text
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("\\b[a-z0-9-]+(\\.[a-z0-9-]+)*\\.[a-z]{2,}\\b");
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[^\\s]+");
    private static final Pattern IP_PATTERN = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
 
    // constructor - takes the email subject and body the user typed in
    public EmailScanner(String emailSubject, String emailBody) {
        this.emailSubject = emailSubject.toLowerCase(); // lowercase so comparison works
        this.emailBody = emailBody.toLowerCase();
        this.matchedKeywords = new ArrayList<>();
        this.matchedDomains = new ArrayList<>();
        this.lookalikeWarnings = new ArrayList<>();
        this.linkWarnings = new ArrayList<>();
        this.database = new ThreatDatabase();          // loads the txt files
    }
 
    // scans the email and checks for suspicious keywords
    public void scanKeywords() {
        for (int i = 0; i < database.getKeywords().size(); i++) {
            String keyword = database.getKeywords().get(i);
            // check if keyword is in subject or body
            if (emailSubject.contains(keyword) || emailBody.contains(keyword)) {
                matchedKeywords.add(keyword); // save the match
            }
        }
    }
 
    // scans the email and checks for suspicious domains
    public void scanDomains() {
        for (int i = 0; i < database.getSuspiciousDomains().size(); i++) { //  how u access an element in an ArrayList
            String domain = database.getSuspiciousDomains().get(i);
            // check if domain appears in the email body
            if (emailBody.contains(domain)) {
                matchedDomains.add(domain); // save the match
            }
        }
    }
 
    // NEW: finds domains pretending to be real brands
    // e.g. paypa1.com (number swapped in) or paypal-security.com (brand name but not the real site)
    public void scanLookalikeDomains() {
        ArrayList<String> checked = new ArrayList<>(); // so the same domain isnt reported twice
        Matcher matcher = DOMAIN_PATTERN.matcher(emailBody);
 
        while (matcher.find()) {
            String domain = matcher.group();
            if (domain.startsWith("www.")) {
                domain = domain.substring(4); // ignore www.
            }
            if (checked.contains(domain)) {
                continue;
            }
            checked.add(domain);
 
            String normalised = normalise(domain); // undo common character tricks
 
            for (int i = 0; i < database.getBrands().size(); i++) {
                String brand = database.getBrands().get(i);
                String official = database.getOfficialDomains().get(i);
 
                if (!normalised.contains(brand)) {
                    continue; // this domain has nothing to do with this brand
                }
                if (domain.equals(official) || domain.endsWith("." + official)) {
                    break; // its the real website, so its fine
                }
                if (!domain.contains(brand)) {
                    // brand only appears after undoing the tricks, so characters were swapped
                    lookalikeWarnings.add(domain + " imitates " + official + " (swapped characters)");
                } else {
                    lookalikeWarnings.add(domain + " uses the name '" + brand + "' but is not " + official);
                }
                break;
            }
        }
    }
 
    // NEW: checks every link in the email for common red flags
    public void scanLinks() {
        Matcher matcher = URL_PATTERN.matcher(emailBody);
 
        while (matcher.find()) {
            String url = matcher.group();
 
            // pull out just the host part, e.g. http://192.168.1.5/login -> 192.168.1.5
            String host = url.substring(url.indexOf("://") + 3);
            int slash = host.indexOf("/");
            if (slash != -1) {
                host = host.substring(0, slash);
            }
            int colon = host.indexOf(":");
            if (colon != -1) {
                host = host.substring(0, colon); // remove port number
            }
 
            if (url.startsWith("http://")) {
                linkWarnings.add("Not secure (http, not https): " + url);
            }
            if (IP_PATTERN.matcher(host).matches()) {
                linkWarnings.add("Uses an IP address instead of a website name: " + url);
            }
            for (int i = 0; i < database.getShorteners().size(); i++) {
                if (host.equals(database.getShorteners().get(i))) {
                    linkWarnings.add("Link shortener hides the real destination: " + url);
                }
            }
        }
    }
 
    // swaps look-alike characters back to letters, e.g. paypa1 -> paypal, micros0ft -> microsoft
    private String normalise(String text) {
        return text.replace("0", "o")
                   .replace("1", "l")
                   .replace("3", "e")
                   .replace("4", "a")
                   .replace("5", "s")
                   .replace("7", "t")
                   .replace("rn", "m")
                   .replace("vv", "w");
    }
 
    // calculates risk level based on how many red flags were found
    public String getRiskLevel() {
        int totalMatches = matchedKeywords.size() + matchedDomains.size()
                + lookalikeWarnings.size() + linkWarnings.size();
        if (totalMatches >= 5) {
            return "HIGH";
        } else if (totalMatches >= 2) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }
 
    // getters so ReportGenerator can access the results
    public ArrayList<String> getMatchedKeywords() {
        return matchedKeywords;
    }
 
    public ArrayList<String> getMatchedDomains() {
        return matchedDomains;
    }
 
    public ArrayList<String> getLookalikeWarnings() {
        return lookalikeWarnings;
    }
 
    public ArrayList<String> getLinkWarnings() {
        return linkWarnings;
    }
 
    public String getRiskLevelResult() {
        return getRiskLevel();
    }
}
 