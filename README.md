# Malicious Traffic Analysis using Wireshark

## Objective
This project aims to leverage my skills in network traffic analysis and malware detection using Wireshark to identify and mitigate cybersecurity threats. The focus is on analyzing DNS queries, HTTP/HTTPS traffic, and extracting Indicators of Compromise (IOCs) to enhance network security and prevent potential breaches.


### Skills Learned

- Malware Detection through Network Traffic Analysis
- DNS Query Analysis for Identifying Suspicious Domains
- File Extraction and Hash Analysis using VirusTotal
- HTTP/HTTPS Protocol Filtering and Investigation
- TCP Stream Reconstruction for Detailed Malware Behavior Analysis


### Tools Used

- Wireshark – Network traffic analysis and packet inspection
- VirusTotal – Hash analysis and malware detection


## Step-by-Step Guide: Analyzing Malware Traffic in Wireshark

### Step 1: Identifying Suspicious DNS Traffic

Malware often uses DNS to communicate with Command-and-Control (C2) servers or malicious websites. Detecting unusual DNS queries is an important step in identifying malware.

#### Capture DNS Traffic in Wireshark

1. Open Wireshark and start capturing network traffic.
2. To focus only on DNS traffic, apply the filter `dns` in the filter bar.

![Alt Text](https://github.com/user-attachments/assets/4748f7d1-3dae-4659-bbc3-870f2a693cb3)

https://github.com/efeemmanuel/Malicious-Traffic-Analysis-using-Wireshark/blob/main/README.md

*Figure 1: Wireshark with DNS filter applied.*

#### Look for Suspicious Domains

- Analyze DNS queries for any unusual or suspicious domains (e.g., domains with strange or uncommon TLDs like `.xyz`, or random-looking domain names).

![Example of suspicious DNS queries in Wireshark](path/to/suspicious-dns-queries-image.png)  
*Figure 2: Example of suspicious DNS queries in Wireshark.*

#### Research the Domain

- Use tools like VirusTotal or DNSDB to check if the domain is flagged as malicious or linked to malware campaigns.
- Investigate if the domain is part of a legitimate service or if it’s associated with known malware infrastructure.

![Screenshot of a domain lookup in VirusTotal or DNSDB](path/to/domain-lookup-image.png)  
*Figure 3: Domain lookup in VirusTotal or DNSDB showing suspicious domain details.*

#### Filter Traffic for the Suspicious Domain

- Once you’ve identified a suspicious domain, filter traffic related to it using the filter: `ip.addr == <resolved_ip>`.
- This will isolate all traffic to and from that domain’s IP address, helping you track any suspicious activity.

![Wireshark filter applied for `ip.addr == <resolved_ip>`](path/to/ip-filter-image.png)  
*Figure 4: Wireshark filter applied for `ip.addr == <resolved_ip>` to show specific traffic.*

### Step 2: Analyzing Traffic Related to DNS Queries

#### Monitor DNS Communication

- Check the packet details for the DNS queries and responses. Pay attention to how often a domain is queried. Repeated attempts to contact a domain might indicate persistent malware communication with a C2 server.

#### Identify Encoded Data in DNS Queries

- Malware can use DNS as a covert communication channel. Inspect DNS queries for unusual or encoded data, which could be malware instructions or data being sent back to the attacker.

![Screenshot of DNS query packet details showing encoded data](path/to/encoded-data-image.png)  
*Figure 5: DNS query packet details showing encoded data.*

### Step 3: Detecting Malware via HTTP/HTTPS Traffic

Malware commonly uses HTTP (port 80) or HTTPS (port 443) to communicate with its C2 server or to download malicious payloads. Investigating HTTP/HTTPS traffic can reveal these interactions.

#### Filter HTTP Requests

- To identify malware traffic, filter for `http.request` in Wireshark.
- This will show all the HTTP requests made by the infected host, including possible requests to malicious domains or for malware downloads.

![Screenshot of HTTP requests in Wireshark](path/to/http-requests-image.png)  
*Figure 6: HTTP requests in Wireshark with `http.request` filter applied.*

#### Export HTTP Objects

- Extract files transmitted over HTTP by going to `File > Export Objects > HTTP` in Wireshark. The files could include malware payloads.

![Wireshark Export Objects window showing HTTP file extraction](path/to/export-objects-image.png)  
*Figure 7: Wireshark Export Objects window showing HTTP file extraction.*

#### Analyze Extracted Files

- After extracting the files, check their hash values using VirusTotal to identify if they contain malware. This applies to file types such as `.exe`, `.dll`, `.php`, `.js`, `.zip`, `.pdf`, etc.

![Screenshot of VirusTotal analyzing the hash of an extracted file](path/to/virus-total-image.png)  
*Figure 8: VirusTotal analyzing the hash of an extracted file.*

### Step 4: Analyzing TCP Streams for Detailed Inspection

#### Follow TCP Stream

- For detailed inspection of a potential malware communication, right-click on an HTTP request packet and select `Follow > TCP Stream`. This will reconstruct the full conversation between the client and server.
- The reconstructed stream shows the full content of the HTTP request and response, providing insight into what data was exchanged.

![Wireshark screenshot showing the Follow TCP Stream option and the reconstructed stream](path/to/tcp-stream-image.png)  
*Figure 9: Wireshark showing the Follow TCP Stream option and the reconstructed stream.*

#### Examine User-Agent and Host Information

- In the TCP stream, check the **User-Agent** (software making the request) and **Host** (domain name of the server). These details can help identify unusual or malicious behavior.
- Use VirusTotal to further check if the host or user-agent is flagged for malicious activity.

![Example of a suspicious TCP stream showing HTTP request details (User-Agent and Host)](path/to/tcp-stream-details-image.png)  
*Figure 10: Suspicious TCP stream showing HTTP request details (User-Agent and Host).*
