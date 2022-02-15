# Red-vs.-Blue-Project
# NETWORK TOPOLOGY 
![Network Topology drawio](https://user-images.githubusercontent.com/89936268/153917768-a7f89f1a-cf49-44a3-8c95-bf086bd99c9d.png)

# RED TEAM - Penetration Test
# NMAP scan:
![nmapscanscreenshot](https://user-images.githubusercontent.com/89936268/153932928-b2f0b074-6d2d-4c56-8756-e50deca1f48d.png)
 
  |   Port  |  State  |      Service        |
  | ------- | ------- | ------------------- |
  | Port 22 |	 Open   |	        SSH         |
  | Port 80 |	 Open   |	       HTTP         |
  ------------------------------------------  
  
  # Aggressive scan:
  An aggressive scan reveals a webserver directory structure on tcp port 80, which is a http port, and two potential usernames of employees – ashton and hannah (which will be more relevant for bruteforcing later):
  
  ![aggresivecommandscreenshot](https://user-images.githubusercontent.com/89936268/153936812-0d668194-a362-4130-b489-f6bb15e2d73a.png)
  
  ![nmapaggressivescreenshot](https://user-images.githubusercontent.com/89936268/153936210-0a4f3dfc-a1db-476d-ae33-6648048c9193.png)

# Vulnerability scan:
scanning for further recon.

Aggressive scan with a vulnerability script reveals:

   - Webdav vulnerability
   - SQL Injection vulnerability across all directories on the webserver
   - CVE-2017-15710 – Apache httpd vulnerability
  
![nmapvulnscanscreenshot](https://user-images.githubusercontent.com/89936268/153944739-a5aea4f0-322b-476e-a862-9cd1a5be95e3.png)
![vuln1screenshot](https://user-images.githubusercontent.com/89936268/154082471-89f43953-4641-4cc7-8397-81a05b7c4e45.png)
![vulnscan2screenshot](https://user-images.githubusercontent.com/89936268/154082515-9748730c-0ccf-476f-a018-cc903c7d5640.png)
![vulnscan3screenshot](https://user-images.githubusercontent.com/89936268/154082557-abdd3872-7e26-4f3c-afba-d935c3234356.png)

# Webserver:
This is the webserver that can investigate further from a browser in the attacker machine:

![websitescreenshot](https://user-images.githubusercontent.com/89936268/154082984-2dd4e751-58f8-4b0a-b7e3-67a869ff122d.png)


In a text document in the blog directory we can see a 3rd username – Ryan, who would have the highest level access as CEO:
![usernamescreenshot](https://user-images.githubusercontent.com/89936268/154083631-b3548aa8-88fb-4138-a047-c1d3634de23b.png)


In the company folders directory, we can see a reference to a "secret_folder" in ALL documents within this directory, which is now a target for this Penetration Test.

![secretfilescreenshot](https://user-images.githubusercontent.com/89936268/154084048-bd30a4fa-d374-4d6c-9e8a-6842b8f40066.png)


The meet_our_team folder confirms the three potential users, and each document references the secret_folder:
In a text document in the blog directory we can see a 3rd username – Ryan, who would have the highest level access as CEO:

![usernamescreenshot](https://user-images.githubusercontent.com/89936268/154083631-b3548aa8-88fb-4138-a047-c1d3634de23b.png)


As seen below, we will need Ashton's password to gain access to the secure hidden folder.
![ashtonloginscreenshot](https://user-images.githubusercontent.com/89936268/154084879-1acbae47-8eed-4f10-965e-6693b22c9620.png)


# Bruteforce:
Now that we have some usernames and a main target - Ashton, using hydra we can attempt to bruteforce the login for the secret_folder.

![hydracommandscreenshot](https://user-images.githubusercontent.com/89936268/154085192-c51c20aa-ec3e-4236-bb29-ad1cae5defc9.png)

![bruteforcescreenshot](https://user-images.githubusercontent.com/89936268/154085852-728a3bd3-774e-4f9c-8f69-4fdd9f966694.png)


# SSH:

ssh ashton@192.168.1.105
Using Ashton's credentials we gained ssh entry into the server.

![sshashtonidscreenshot](https://user-images.githubusercontent.com/89936268/154086654-d208af03-af0f-4c3f-be38-0a9598587caa.png)

![ashtonrootflagscreenshot](https://user-images.githubusercontent.com/89936268/154086705-c5763231-e883-464c-8c5b-dcee7c42d5a7.png)

![sshflagscreenshot](https://user-images.githubusercontent.com/89936268/154086779-b8700020-ae4f-48be-9463-5de5caa54b7e.png)


# Vulnerabilities:

Webserver

1. Usernames are employee first names.
These are too obvious and most likely discoverable through Google Dorking. All are high level employees of the company which are more vulnerable, and certainly easier to find in the company structure in publicly available material.

  - Attackers can (with very little investigation) create a wordlist of usernames of employees for bruteforcing.
  - Usernames should not include the person's name.

2. Ryan's password hash was printed into a document, publicly available on the webserver.
The password hash is highly confidential and vulnerable once an attacker can access it.

CWE-256: Unprotected Storage of Credentials

https://cwe.mitre.org/data/definitions/256.html

  - A password hash is one of the highest targets for an attacker that is trying to gain entry; being able to navigate to one in a browser through minimal      effort is a critical vulnerability.
  - Password hashes should remain in the /etc/shadow directory with root only access in the system, and not be published or copied anywhere.

3. CWE-759: Use of a One-Way Hash without a Salt.
https://cwe.mitre.org/data/definitions/759.html

CWE-916: Use of Password Hash With Insufficient Computational Effort

https://cwe.mitre.org/data/definitions/916.html

Ryan's password is only hashed, but not salted. A password hash can be run through apps to crack the password, however a salted hash will be almost impossible to crack.

  - A simple hash can be cracked with tools in linux or through websites, in this case it took seconds to crack Ryan's hash.
  - Salt hashes.

4. CWE-521: Weak Password Requirements.
https://cwe.mitre.org/data/definitions/521.html

Passwords need to have a minimum requirement of password length and use of mixed characters and case.

  - linux4u is a simple phrase with very common word substitution – 4=for, u=you. and leopoldo is a common name that could easily be bruteforced with a common password list.
  - Require strong passwords that exclude phrases and names, minimum 8 characters, mixed characters that include a combination of lower case, upper case, special characters and numbers.
  - Consider implementing multi-factor authentication.

Apache 2.4.29
  1. CVE-2017-15710
This potential Apache httpd vulnerability was picked up by nmap and relates to a configuration that verifies user credentials; a particular header value is searched for and if it is not present in the charset conversion table, it reverts to a fallback of 2 characters (eg. en-US becomes en). While this risk is unlikely, if there is a header value of less than 2 characters, the system may crash.

   - This vulnerability has the potential to force a Denial of Service attack.
   - As this vulnerability applies to a range of Apache httpd versions from 2.0.23 to 2.4.29, upgrading to the latest version 2.2.46 may mitigate this risk.
  
  2. CVE-2018-1312
While this vulnerability wasn't picked up in any scans, the apache version remains vulnerable. From cve-mitre "When generating an HTTP Digest authentication challenge, the nonce sent to prevent reply attacks was not correctly generated using a pseudo-random seed. In a cluster of servers using a common Digest authentication configuration, HTTP requests could be replayed across servers by an attacker without detection."

   - With this vulnerability, an attacker would be able to replay HTTP requests across a cluster of servers (that are using a common Digest authentication configuration), whilst avoiding detection.
   - Apache httpd versions 2.2.0 to 2.4.29 are vulnerable - upgrade to 2.2.46
 
 3. CVE-2017-1283
Mod_session is configured to forward its session data to CGI applications

   - With this vulnerability, a remote user may influence their content by using a "Session" header.
   - Apache httpd versions 2.2.0 to 2.4.29 are vulnerable - upgrade to 2.2.46
 
 4. CVE-2017-15715
This vulnerability relates to malicious filenames, in which the end of filenames can be matched/replaced with '$'

   - In systems where file uploads are externally blocked, this vulnerability can be exploited to upload malicious files
   - Apache httpd versions 2.2.0 to 2.4.29 are vulnerable - upgrade to 2.2.46
   - 
