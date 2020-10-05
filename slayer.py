import os
import time
from pathlib import Path
import sys
import json
# from shodan import Shodan
# from slackclient import SlackClient

#SHODAN_API_KEY = os.environ["SHODAN_API_KEY"]
with open('config.json', 'r') as config:
    config_json = json.load(config)

slack_token = config_json['slack_token']
slack_hook = config_json['slack_hook']

# slack_token = os.environ["SLACK_API_TOKEN"]
# slack_hook = os.environ["SLACK_HOOK"]
# sc = SlackClient(slack_token)

#domain = input("Enter domain : ") 
#print(domain)
domain = sys.argv[1]

def logo():
	print('''

 ____                           ____
|  _ \ ___  ___ ___  _ __      / ___|| | __ _ _   _  ___ _ __ 
| |_) / _ \/ __/ _ \| '_ \ ____\___ \| |/ _` | | | |/ _ \ '__|
|  _ <  __/ (_| (_) | | | |_____|__) | | (_| | |_| |  __/ |   
|_| \_\___|\___\___/|_| |_|    |____/|_|\__,_|\__, |\___|_|   
                                              |___/        
How to Run: python3 slayer.py <domain_name>


		''')
def subdomain(domain):
	print("[*] Subdomains Function running")
	os.system("mkdir ~/recon/{}/uphost -p 2>/dev/null; touch ~/recon/{}/uphost/uphost.txt".format(domain,domain))
	os.system("python ~/tools/Sublist3r/sublist3r.py -d {} -t 15 -v -o ~/recon/{}/sublist3r.txt".format(domain,domain))

	os.system("curl -s https://certspotter.com/api/v0/certs?domain={} 2>/dev/null | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep -i {} > ~/recon/{}/certspotter.txt".format(domain,domain,domain))
	os.system("amass enum --passive -d {} -o ~/recon/{}/amass-{}.txt".format(domain,domain,domain))	
	os.system("findomain -t {} -u ~/recon/{}/findomain-{}.txt".format(domain,domain,domain))
	os.system("assetfinder --subs-only {} | tee -a ~/recon/{}/asseet-{}.txt".format(domain,domain,domain))
	os.system("subfinder -d {} > ~/recon/{}/subfinder-{}.txt".format(domain,domain,domain))
	os.system("curl -s https://crt.sh/\?q\=\%.{}\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > ~/recon/{}/crt-{}.txt".format(domain,domain,domain))
	os.system("cd ~/recon/"+domain+"/ ; mkdir merge 2>/dev/null")
	os.system("cd ~/recon/"+domain+"/  ; cat *.txt | sort -u > ./merge/"+time.strftime("%Y%m%d-%H%M%S")+".txt")
	os.system("cd ~/recon/"+domain+"/merge ; cat *.txt | sort -u > unique.txt")
	
	#slack-notifier-for-new-domains
	if os.path.isfile("/root/recon/"+domain+"/merge/unique.txt"):
		os.system( "cd ~/recon/" + domain + "/merge ; curl -F file=@unique.txt -F \"initial_comment=New Subdomains Discovered !!!\" -F channels=subdomains -H \"Authorization: Bearer " + slack_token + "\" https://slack.com/api/files.upload ")
	else :
		os.system("cd ~/recon/"+domain+"/merge ; curl -X POST -H 'Content-type: application/json' --data '{\"text\":\"No new Subdomains found !!\"}' https://hooks.slack.com/services/"+slack_hook+" 2>/dev/null 1>/dev/null")
	
			
def takeover(domain):
	print("[*] Takeover running")
	os.system("mkdir ~/recon/{}/takeover/ 2>/dev/null".format(domain))
	os.system("subjack -w ~/recon/{}/uphost/uphost_tmp.txt -c ~/go/src/github.com/haccer/subjack/fingerprints.json -t 100 -timeout 30 -o ~/recon/{}/takeover/takeover.txt -ssl -v".format(domain,domain))
	# os.system("cd ~/tools ; cat ~/recon/"+domain+"/merge/unique.txt | ./aquatone -ports xlarge -out ~/recon/"+domain+"/aquatone/")
	os.system("cd ~/recon/"+domain+"/takeover/ ; curl -F file=@takeover.txt -F \"initial_comment=Check report for **takeover** !!!\" -F channels=subdomain-takeover -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 1>/dev/null 2>/dev/null")
	

def screenshots(domain):
	print("[*] screenshots running")
	os.system("mkdir ~/recon/"+domain+"/screenshots/ 2>/dev/null ; rm -rf ~/recon/"+domain+"/screenshots/* 2>/dev/null")
	os.system("cd ~/tools/ ; ./gowitness file -f ~/recon/{}/uphost/uphost.txt -t 50 -P ~/recon/{}/screenshots/".format(domain,domain))
	os.system("cd ~/recon/"+domain+"/screenshots/ ; zip -r screenshots.zip * ")
	os.system("cd ~/recon/"+domain+"/screenshots/ ; curl -F file=@screenshots.zip -F \"initial_comment=screenshots for "+domain+" done !!!\" -F channels=screenshots -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
	

def recon(domain):
	print("[*] Recon running")
	os.system("cat ~/recon/{}/uphost/uphost_tmp.txt  > ~/recon/{}/uphost/ipv4.txt".format(domain,domain))
	os.system("cd ~/recon/{}/uphost ; nmap -Pn -T4 -iL ipv4.txt -oN nmap-i4.txt".format(domain))
	# os.system("cat ~/recon/{}/uphost/ip.txt | grep -F ':' > ~/recon/{}/uphost/ipv6.txt".format(domain,domain))
	# os.system("cd ~/recon/{}/uphost ; nmap -Pn -T5 -6 -iL ipv6.txt -oN nmap-i6.txt".format(domain))
	os.system("cd ~/recon/"+domain+"/uphost/ ; curl -F file=@nmap-i4.txt -F \"initial_comment=nmap IPv4 scan completed for domain "+domain+" !!!\" -F channels=nmap -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
	os.system("cd ~/recon/"+domain+"/uphost/ ; curl -F file=@nmap-i6.txt -F \"initial_comment=nmap IPv6 scan completed for domain "+domain+" !!!\" -F channels=nmap -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")


def directories(domain):
	print("[*] directories running")
	os.system("mkdir ~/recon/{}/directories/".format(domain))
	lines = [line.rstrip('\n') for line in open('/root/recon/{}/uphost/uphost_tmp.txt'.format(domain))]
	with open('/root/recon/{}/uphost/uphost_tmp.txt'.format(domain)) as myfile:
		num_lines = sum(1 for line in myfile if line.rstrip('\n'))
	# num_lines = sum(1 for line in open("~/recon/{}/uphost/uphost_tmp.txt".format(domain)))
	print(num_lines)
	for i in range(num_lines):
		os.system("cd ~/recon/"+domain+"/directories/ ; ~/tools/dirsearch/dirsearch.py -u https://"+lines[i]+" -e * -x 400,403,406,409,410,412,415,418,423,426,431,450,429,500,503,506,509,598 -t 50 -b --simple-report="+lines[i]+".txt")
		os.system("cd ~/recon/"+domain+"/directories/ ; curl -F file=@"+lines[i]+".txt -F \"initial_comment=Dirsearch result for domain "+lines[i]+" !!!\" -F channels=directories -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
	

	
def uphost(domain):
	print("[*] uphost Running")
	os.system("cat ~/recon/"+domain+"/merge/unique.txt | filter-resolved > ~/recon/"+domain+"/uphost/uphost_tmp.txt")
	os.system("cat ~/recon/"+domain+"/uphost/uphost_tmp.txt | httpx -threads 50 > ~/recon/"+domain+"/uphost/uphost.txt")
	os.system("cd ~/recon/"+domain+"/uphost ; curl -F file=@uphost.txt -F \"initial_comment=New **Up** Subdomains Discovered !!!\" -F channels=uphost -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
	
def gau(domain):
	print("[*] gau Running")
	os.system("mkdir ~/recon/{}/gau/".format(domain))
	os.system("cat /root/recon/{}/uphost/uphost_tmp.txt | gau >> ~/recon/{}/gau/gau.txt".format(domain,domain))
	os.system("cd ~/recon/"+domain+"/gau ; curl -F file=@gau.txt -F \"initial_comment=Wayback URLs\" -F channels=gau -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")

def nuclei(domain):
	print("[*] Nuclei Running")
	os.system("mkdir ~/recon/{}/nuclei/".format(domain))
	os.system("cat /root/recon/{}/uphost/uphost.txt | nuclei -t /root/tools/nuclei-templates/cves/ -o ~/recon/{}/nuclei/cves.txt".format(domain,domain))
	os.system("cd ~/recon/"+domain+"/nuclei ; curl -F file=@cves.txt -F \"initial_comment=CVE Output\" -F channels=nuclei -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
	os.system("cat /root/recon/{}/uphost/uphost_tmp.txt | nuclei -t /root/tools/nuclei-templates/subdomain-takeover/ -o ~/recon/{}/nuclei/subdomain-takeover.txt".format(domain,domain))
	os.system("cd ~/recon/"+domain+"/nuclei ; curl -F file=@subdomain-takeover.txt -F \"initial_comment=Subdomain Takeover\" -F channels=subdomain-takeover -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
	os.system("cat /root/recon/{}/uphost/uphost.txt | nuclei -t /root/tools/nuclei-templates/files/ -o ~/recon/{}/nuclei/files.txt".format(domain,domain))
	os.system("cd ~/recon/"+domain+"/nuclei ; curl -F file=@files.txt -F \"initial_comment=Files Output\" -F channels=nuclei -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
	os.system("cat /root/recon/{}/gau/gau.txt | nuclei -t /root/tools/nuclei-templates/tokens/ -o ~/recon/{}/nuclei/tokens.txt".format(domain,domain))
	os.system("cd ~/recon/"+domain+"/nuclei ; curl -F file=@tokens.txt -F \"initial_comment=tokens Output\" -F channels=nuclei -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
	os.system("cat /root/recon/{}/uphost/uphost.txt | nuclei -t /root/tools/nuclei-templates/vulnerabilities/ -o ~/recon/{}/nuclei/vulnerabilities.txt".format(domain,domain))
	os.system("cd ~/recon/"+domain+"/nuclei ; curl -F file=@vulnerabilities.txt -F \"initial_comment=vulnerabilities Output\" -F channels=nuclei -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
	os.system("cat /root/recon/{}/uphost/uphost.txt | nuclei -t /root/tools/nuclei-templates/panels/ -o ~/recon/{}/nuclei/panels.txt".format(domain,domain))
	os.system("cd ~/recon/"+domain+"/nuclei ; curl -F file=@panels.txt -F \"initial_comment=panels Output\" -F channels=nuclei -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")


# 	#print ("domain")
logo()
subdomain(domain)
uphost(domain)
takeover(domain)
screenshots(domain)
gau(domain)
directories(domain)
nuclei(domain)
# ip(domain)
recon(domain)


