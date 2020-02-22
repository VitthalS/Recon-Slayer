import os
import time
from pathlib import Path
import sys 
# from shodan import Shodan
# from slackclient import SlackClient

#SHODAN_API_KEY = os.environ["SHODAN_API_KEY"]
slack_token = os.environ["SLACK_API_TOKEN"]
slack_hook = os.environ["SLACK_HOOK"]
# sc = SlackClient(slack_token)

#domain = input("Enter domain : ") 
#print(domain)
domain = sys.argv[1]

def subdomain(domain):
	print("[*] Subdomains Function running")
	os.system("mkdir ~/recon/{}/uphost -p 2>/dev/null; touch ~/recon/{}/uphost/uphost.txt".format(domain,domain))
	os.system("python ~/tools/Sublist3r/sublist3r.py -d {} -t 10 -v -o ~/recon/{}/sublist3r.txt".format(domain,domain))

	os.system("curl -s https://certspotter.com/api/v0/certs?domain={} 2>/dev/null | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep -i {} > ~/recon/{}/certspotter.txt".format(domain,domain,domain))
	##os.system("python ~/tools/censys-subdomain-finder/censys_subdomain_finder.py {} -o ~/recon/{}censys.txt".format(domain,domain))		
	os.system("cd ~/tools/ ; ./gobuster dns -t 50 -d {} -w ~/tools/commonspeak2-wordlists/subdomains/subdomains.txt -o ~/recon/{}/gobuster.txt ; | cut -d ':' -f3 | sort -u > ~/recon/{}/gobuster-final.txt ; rm ~/recon/{}/gobuster.txt".format(domain,domain,domain,domain))
	#os.system("aquatone-discover --domain {}".format(domain))
	os.system("curl -s \"http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=text&fl=original&collapse=urlkey\" |sort| sed -e 's_https*://__' -e \"s/\/.*//\" -e 's/:.*//' -e 's/^www\.//' | uniq > ~/recon/{}/waybackdomains.txt".format(domain,domain))
	os.system("amass enum -d {} -o ~/recon/{}/amass-{}.txt".format(domain,domain,domain))	
	os.system("cd ~/tools/ ; python crt.py --domain {} > ~/recon/{}/crt.txt".format(domain,domain))
	os.system("cd ~/recon/"+domain+"/ ; mkdir merge 2>/dev/null")
	#os.system("cat ~/aquatone/{}/hosts.txt | cut -d ',' -f1 > ~/recon/{}/aquatone.txt ".format(domain,domain))
	os.system("cd ~/recon/"+domain+"/  ; cat *.txt | sort -u > ./merge/"+time.strftime("%Y%m%d-%H%M%S")+".txt")
	os.system("cd ~/recon/"+domain+"/merge ; ( cat *.txt ) | sort | uniq -c | awk '$1==1 {print $2}' > unique.txt")
	
	#slack-notifier-for-new-domains
	mypath = Path("~/recon/"+domain+"/merge/unique.txt")
	if mypath.stat().st_size != 0 :
		os.system("cd ~/recon/"+domain+"/merge ; curl -F file=@unique.txt -F \"initial_comment=New Subdomains Discovered !!!\" -F channels=subdomains -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
		uphost(domain)
	elif mypath.stat().st_size == 0 :
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
	os.system("cd ~/tools/webscreenshot/ ; python webscreenshot.py -i ~/recon/{}/uphost/uphost.txt -o ~/recon/{}/screenshots/".format(domain,domain))
	os.system("cd ~/recon/"+domain+"/screenshots/ ; zip -r screenshots.zip * ")
	os.system("cd ~/recon/"+domain+"/screenshots/ ; curl -F file=@screenshots.zip -F \"initial_comment=screenshots for "+domain+"done !!!\" -F channels=screenshots -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
	

def ip(domain):
	print("[*] IP running")
	lines = [line.rstrip('\n') for line in open('~/recon/{}/uphost/uphost_tmp.txt'.format(domain))]
	num_lines = sum(1 for line in open('~/recon/{}/uphost/uphost_tmp.txt'.format(domain)))
	for i in range(num_lines):
		os.system("dig +short "+lines[i]+" > ~/recon/{}/uphost/ip_tmp.txt ; sort -u ~/recon/{}/uphost/ip_tmp.txt > ~/recon/{}/uphost/ip.txt ".format(domain,domain,domain,domain))
		os.system("sort -u ~/recon/{}/uphost/ip_tmp.txt > ~/recon/{}/uphost/ip.txt ".format(domain,domain))


def recon(domain):
	print("[*] Recon running")
	os.system("cat ~/recon/{}/uphost/ip.txt | grep -F '.' > ~/recon/{}/uphost/ipv4.txt".format(domain,domain))
	os.system("cd ~/recon/{}/uphost ; nmap -Pn -T5 -iL ipv4.txt -oN nmap-i4.txt".format(domain))
	os.system("cat ~/recon/{}/uphost/ip.txt | grep -F ':' > ~/recon/{}/uphost/ipv6.txt".format(domain,domain))
	os.system("cd ~/recon/{}/uphost ; nmap -Pn -T5 -6 -iL ipv6.txt -oN nmap-i6.txt".format(domain))
	os.system("cd ~/recon/"+domain+"/uphost/ ; curl -F file=@nmap-i4.txt -F \"initial_comment=nmap IPv4 scan completed for domain "+domain+" !!!\" -F channels=nmap -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
	os.system("cd ~/recon/"+domain+"/uphost/ ; curl -F file=@nmap-i6.txt -F \"initial_comment=nmap IPv6 scan completed for domain "+domain+" !!!\" -F channels=nmap -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")


def directories(domain):
	print("[*] directories running")
	os.system("mkdir ~/recon/{}/directories/ 2>/dev/null".format(domain))

	lines = [line.rstrip('\n') for line in open('~/recon/{}/uphost/uphost_tmp.txt'.format(domain))]
	num_lines = sum(1 for line in open('~/recon/{}/uphost/uphost_tmp.txt'.format(domain)))
	print(num_lines)
	for i in range(num_lines):
		# os.system("cd ~/recon/"+domain+"/directories/ ; ~/tools/dirsearch/dirsearch.py -u "+lines[i]+" -e * -x 400,403,406,409,412,415,418,423,426,431,450,429,500,503,506,509,598 -t 50 --simple-report="+lines[i]+".txt")
		os.system("cd ~/recon/"+domain+"/directories/ ; ~/tools/dirsearch/dirsearch.py -u https://"+lines[i]+" -e * -x 400,403,406,409,410,412,415,418,423,426,431,450,429,500,503,506,509,598 -t 50 --simple-report="+lines[i]+".txt")
		os.system("cd ~/recon/"+domain+"/directories/ ; curl -F file=@"+lines[i]+".txt -F \"initial_comment=Dirsearch result for domain "+lines[i]+" !!!\" -F channels=directories -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
	

	
def uphost(domain):
	print("[*] uphost Running")
	os.system("cat ~/recon/"+domain+"/merge/unique.txt | filter-resolved > ~/recon/"+domain+"/uphost/uphost_tmp.txt")
	os.system("cat ~/recon/"+domain+"/uphost/uphost_tmp.txt | httprobe > ~/recon/"+domain+"/uphost/uphost.txt")
	mypath = Path("~/recon/"+domain+"/uphost/uphost.txt")
	if mypath.stat().st_size != 0 :
		os.system("cd ~/recon/"+domain+"/uphost ; curl -F file=@uphost.txt -F \"initial_comment=New **Up** Subdomains Discovered !!!\" -F channels=uphost -H \"Authorization: Bearer "+slack_token+"\" https://slack.com/api/files.upload 2>/dev/null 1>/dev/null")
		directories(domain)
		screenshots(domain)
		ip(domain)
		recon(domain)
	elif mypath.stat().st_size == 0 :
		os.system("cd ~/recon/"+domain+"/uphost ; curl -X POST -H 'Content-type: application/json' --data '{\"text\":\"No new *Up* Subdomains found !!\"}' https://hooks.slack.com/services/"+slack_hook+" 2>/dev/null 1>/dev/null")
	

	#print ("domain")
subdomain(domain)

directories(domain)
takeover(domain)
screenshots(domain)
ip(domain)
recon(domain)


