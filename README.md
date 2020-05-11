# Recon-Slayer
Noobs Python script to automate your reconnaissance and get result on your slack.


## Prerequisite 
- Create a slack workspace
- Generate slack token from : https://api.slack.com/custom-integrations/legacy-tokens
- Generate webhook token from here : https://api.slack.com/incoming-webhooks
- Set slack_token & slack_hook in config.json

        slack_token=XXX-XXX
        slack_hook=XXX-XXX

- Create below channels in your workspace
        
        subdomains
        uphost
        subdomain-takeover
        screenshots
        nmap
        directories

## Install 
1. git clone https://github.com/VitthalS/Recon-Slayer.git
2. chmod +x tools.sh
3. ./tools.sh
4. Add slack token and webhook in config.js


## Usage

	python3 slayer.py example.com

Result will be saved in `~/recon/example.com/`

If you want to see the screenshots from your VPS you can use [ssslide](https://github.com/tehryanx/ssslide)

## To-Do
- Add gau to detect XSS, Open Redirect vulns.
- Add S3 Scanner
- Add Wayback URLs support
- Add subjs
 
