# Passive Information Gathering & Footprinting
Passive information gathering refers to any information gathering technique that doesn't involve us using anything other than simple commands and readily available information to help us build an effective attack.
## Google Dorks
Google offers an inbuilt solution to help advanced users get more effective searches, purely for browsing optimization. However, with some clever queries we can get really valuable information about certain possibly-vulnerable websites that might save us hours of actual hacking. First, we will list the most valuable operators for our purposes. 

| Dork          | Description                                          | Example                         |
| :------------ | ---------------------------------------------------- | ------------------------------- |
| " " (quotes)  | Search for exact matches                             | "FistName LastName"             |
| site:         | Search only in a specific website                    | "FN LN" and site:target.com     |
| AND/OR        | Standard logic operators                             | "FN LN" OR "LN FN"              |
| intitle:      | Search pages that contain  a specific word           | intitle:"login"                 |
| filetype:     | Search files of a specific type                      | filetype:pdf                    |
| intext:       | Search inside the text of a page                     | intext:"FN LN"                  |
| - (minus)     | Exclude a parameter from the search                  | -site:wordpress.com             |
| \* (star)     | Replaces unknown words                               | "Name: Eufrasio,  LastName: \*" |
| ext:          | Similar to filetype, but for file extensions instead | ext:sql                         |
| related:      | Search for similar sites                             | related:google.com              |
| inurl:        | Search for words inside of a url                     | inurl:admin                     |
| allinurl:     | Search for multiple words inside of a url            | allinurl:admin password         |
| allintitle:   | Same as allinurl but for titles                      | allintitle:"index of" "backup"  |
| after/before: | Filters by date (yyyy-mm-dd)                         | "data breach" before:2023-12-31 |
| cache:        | Shows local cached version of a page                 | cache:upm.es                    |
### Useful examples
To find a plethora of other examples, you can visit the google hacking database in exploit-db.com (link pinned in homepage by default in kali).

| Dork                        | Explanation                                                                                                                                    |
| :-------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `inurl: "index.php?id="`    | Returns possible login pages that might me vulnerable to sqli                                                                                  |
| `site:uat.* \* inurl:login` | Returns User Acceptance Testing login pages (possibly vulnerable since they are pre-production pages only for stakeholder or end-user testing) |
| `intitle:index of/etc/ssh`  | Returns pages that might contain ssh keys (**_bad_**, don't do this)                                                                           |


## whois
The command `whois` is a preinstalled command in kali that returns a list of all public information about a domain. This is interesting because in the midst of all the data we can find some information that can prove useful for certain attacks. However, if we try to search for a lesser known domain, the database from which `whois` pulls its data from might not have any available info for us. Printed text might be too confusing, I recommend redirecting the output in a txt file, or piping into another command to filter the output.

`whois [OPTION]... OBJECT...`

| Data        | Attack                                                                                                                   |
| :---------- | ------------------------------------------------------------------------------------------------------------------------ |
| email       | spear-phishing                                                                                                           |
| Name Server | DOS?, DNS attack                                                                                                         |
| Directions  | Physical attacks (highly illegal, but useful to know if your company's location is public to recommend on-site security) |
| Update Date | Vulnerable downgraded versions                                                                                           |
## The Harvester
This is yet another preinstalled tool in the kali suite. It allows us to get a list of useful ips, emails, hosts or even people, given just a domain. However, as cool as it is, we need to upload the API keys of the services we want to use to the api-keys.yaml file (found by default in /etc/theHarvester.
`theHarvester -d [domain] OTHER-PARAM`

| Flag | Description                            | Example         |
| :--- | -------------------------------------- | --------------- |
| `-d` | Domain to search                       | `-d amazon.com` |
| `-l` | Limit of results                       | `-l 500`        |
| `-b` | Search engine (all is a valid sentece) | `-b shodan`     |
## Shodan

c
