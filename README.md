
# Phishing Email Detector
 
A rule-based phishing email detector written in Java. Paste in an email's subject and body, and it checks for common phishing red flags, rates the risk as LOW, MEDIUM or HIGH, and prints a threat report with a recommendation.
 
**Try it in your browser:** [Live demo](https://hadispazhand.github.io/phishing-email-detector/)
 
## What it detects
 
- **Suspicious keywords** such as "urgent", "verify your account" and "unusual activity"
- **Known suspicious domains** from a threat list
- **Lookalike domains** that imitate real brands, e.g. `paypa1.com` (characters swapped) or `paypal-security.com` (brand name on an unofficial site)
- **Risky links**, including `http` instead of `https`, raw IP addresses and link shorteners like `bit.ly`
Risk is based on the total number of red flags: 5 or more is HIGH, 2 to 4 is MEDIUM, and 0 or 1 is LOW.
 
## How it works
 
| Class | Role |
|---|---|
| `Main` | Reads the email from the user and runs the scans |
| `ThreatDatabase` | Loads the detection lists from the `Data` folder |
| `EmailScanner` | Runs each check and calculates the risk level |
| `ReportGenerator` | Prints the threat report with a unique report ID |
 
The detection lists live in plain text files, so they can be updated without changing or recompiling the code:
 
| File | Contents |
|---|---|
| `Data/Keyword.txt` | Phishing keywords and phrases, one per line |
| `Data/Suspicious_domain.txt` | Known suspicious domains, one per line |
| `Data/Brands.txt` | Brand names and their official domains, e.g. `paypal,paypal.com` |
| `Data/Shorteners.txt` | Link shortener domains, one per line |
 
## How to run
 
Requires Java (JDK 8 or later). From the project folder:
 
```
javac *.java
java Main
```
 
Enter the subject, then paste the email body and type `END` on a new line when finished.
 
## Limitations and next steps
 
Rule-based detection catches common tricks, but a carefully written phishing email with no red-flag words could still get through. Real email security layers in sender authentication (SPF, DKIM, DMARC), link reputation checks and user awareness training. Ideas for future versions:
 
- Weighted scoring, so a fake domain counts for more than a single keyword
- A sender check that flags mismatched display names and free email providers
- Saving each report to a log file
## About
 
Built by [Hadis Pazhand](https://www.linkedin.com/in/hadis-pazhand-5264311b1/), Bachelor of Cybersecurity student at La Trobe University.
 
