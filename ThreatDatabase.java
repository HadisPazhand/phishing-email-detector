// Reads the txt files in the Data folder into ArrayLists
// Private fields, getters to access the lists
// Methods: loadKeywords(), loadDomains(), loadBrands(), loadShorteners()
 
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Scanner;
 
public class ThreatDatabase {
 
    // private so nothing outside this class can touch it
    private ArrayList<String> keywords;
    private ArrayList<String> suspiciousDomains;
    private ArrayList<String> brands;          // e.g. paypal
    private ArrayList<String> officialDomains; // e.g. paypal.com (same position as its brand)
    private ArrayList<String> shorteners;      // e.g. bit.ly
 
    // constructor - runs automatically when ThreatDatabase object is created
    public ThreatDatabase() {
        keywords = new ArrayList<>();
        suspiciousDomains = new ArrayList<>();
        brands = new ArrayList<>();
        officialDomains = new ArrayList<>();
        shorteners = new ArrayList<>();
        loadList("Data/Keyword.txt", keywords);
        loadList("Data/Suspicious_domain.txt", suspiciousDomains);
        loadList("Data/Shorteners.txt", shorteners);
        loadBrands("Data/Brands.txt");
    }
 
    // reads each line of a file into a list
    // blank lines are skipped - an empty keyword would match every email
    private void loadList(String filePath, ArrayList<String> list) {
        try {
            Scanner fileScanner = new Scanner(new File(filePath));
            while (fileScanner.hasNextLine()) {
                String line = fileScanner.nextLine().trim().toLowerCase(); // trim spaces, make lowercase
                if (!line.isEmpty()) {
                    list.add(line);
                }
            }
            fileScanner.close();
        } catch (IOException e) {
            // if file not found, dont crash the program
            System.out.println("Error loading " + filePath);
        }
    }
 
    // reads Brands.txt where each line looks like: paypal,paypal.com
    private void loadBrands(String filePath) {
        try {
            Scanner fileScanner = new Scanner(new File(filePath));
            while (fileScanner.hasNextLine()) {
                String line = fileScanner.nextLine().trim().toLowerCase();
                String[] parts = line.split(",");
                if (parts.length == 2) {
                    brands.add(parts[0].trim());
                    officialDomains.add(parts[1].trim());
                }
            }
            fileScanner.close();
        } catch (IOException e) {
            System.out.println("Error loading " + filePath);
        }
    }
 
    // getters so other classes can access the lists
    public ArrayList<String> getKeywords() {
        return keywords;
    }
 
    public ArrayList<String> getSuspiciousDomains() {
        return suspiciousDomains;
    }
 
    public ArrayList<String> getBrands() {
        return brands;
    }
 
    public ArrayList<String> getOfficialDomains() {
        return officialDomains;
    }
 
    public ArrayList<String> getShorteners() {
        return shorteners;
    }
}