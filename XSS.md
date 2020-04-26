XSS - Cross-site scripting 

Note: You'll find better information in the [OWASP page](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)).
Useful resources:
- [OWASP page](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))
- [XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Testing for Stored Cross site scripting](https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002))
- [Testing for Reflected Cross site scripting](https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001))
- [Testing for DOM-based Cross site scripting](hhttps://www.owasp.org/index.php/Testing_for_DOM-based_Cross_site_scripting_(OTG-CLIENT-001))

As a brief description, XSS are flaws in a Web application that allow an attacker to execute scripts in the context of other users' browsers. Say you have an attacker named Willy and a normal user named Norman. Willy has the same capabilities in the Web application that Norman has, but Willy has discovered an XSS flaw in the Web application. Then, Willy can make use of this to execute JavaScript code in Norman's browser. This JavaScript script will have access to cookies, session tokens, authentication information, etc. Willy can then obtain information of Norman's account, redirect him to a page of his own (by rewritting the HTML) or perform operations on Norman's behalf.

The attacks require a Web application that takes untrusted input from the users and, without validating this data, it includes it as dynamic content that that is sent to other web users. There are 3 main types of XSS attacks, according to OWASP's page: stored, reflected and DOM-based. I'll test our target application for these.

I've selected the application called Red-Social-Asociacion, hosted in [GitHub](https://github.com/MecatronicaUncu/Red-Social-Asociacion). A friend of mine and I wrote this applications some years ago, when we were just starting in web programming. Because of that, I assume that it will have many flaws.

# Before starting

- We'll use Firefox proxyed through ZAP, so as to get all HTTP communication in ZAP and then take advantage of it
- Beware that some browsers might have protection against input of scripts. If this happens, you can always send requests via ZAP or curl.

# Stored XSS attacks

To test for stored xss attacks, we need to analyze where the application is requesting user input. So, let's first create a user for Willy and browse around. The web application will send an activation email, but it doesn't have a proper SMTP server configured. So, we'll need to access docker, using
`sudo docker ps
sudo docker exec -it {docker_name} /bin/bash`

Then we login to neo4j database
`cd ~/Red-Social-Asociacion/server/bin/neo4j-community-2.3.3/bin
./neo4j-shell`

Then we set the 'active' field for our user to 1 (you get the ID_USER from the response to the signup request, done before)
` MATCH (u:User) WHERE ID(u)={ID_USER} SET u.active=1`

