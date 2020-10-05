#! /bin/bash

sudo apt-get -y update
sudo apt-get -y upgrade
sudo apt install snapd


sudo apt-get install -y libcurl4-openssl-dev
sudo apt-get install -y libssl-dev
sudo apt-get install -y jq
sudo apt-get install -y ruby-full
sudo apt-get install -y libxss1 libappindicator1 libindicator7
sudo apt-get install -y libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev
sudo apt-get install -y build-essential libssl-dev libffi-dev python-dev
sudo apt-get install -y python-setuptools
sudo apt-get install -y libldns-dev
sudo apt-get install -y python3-pip
sudo apt-get install -y python2.7 python-pip
sudo apt-get install -y python-dnspython
sudo apt-get install -y git
sudo apt-get install -y rename
sudo apt-get install -y xargs
sudo apt-get install -y phantomjs
sudo apt-get install -y nmap
sudo apt-get install -y curl
sudo apt-get install -y jq



#create a tools folder in ~/
mkdir ~/tools
cd ~/tools/

echo "Installing Golang"
wget https://dl.google.com/go/go1.13.4.linux-amd64.tar.gz
sudo tar -xvf go1.13.4.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
echo 'export GOROOT=/usr/local/go' >> ~/.bash_profile
echo 'export GOPATH=$HOME/go'	>> ~/.bash_profile			
echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bash_profile	
source ~/.bash_profile


echo "Installing Sublist3r"
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r*
pip install -r requirements.txt
cd ~/tools/
echo "done"

echo "Istalling Amass"
snap install amass
echo "done"

echo "Istalling Amass"
snap install amass
echo "done"

echo "Installing Findomain"
sudo wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux -O findomain
chmod +x findomain
cp ~/tools/findomain*/findomain /usr/bin/
echo "done"

echo "Installing Subfinder"
go get -v github.com/projectdiscovery/subfinder/cmd/subfinder
echo "done"

echo "Installing assetfinder"
go get -u github.com/tomnomnom/assetfinder
cp ~/go/bin/assetfinder /usr/bin
echo "done"

echo "Installing subjack"
go get github.com/haccer/subjack
echo "done"

echo "Installing gowitness"
cd /root/tools ; wget https://github.com/sensepost/gowitness/releases/download/2.1.2/gowitness-2.1.2-linux-amd64 ; mv gowitness-2.1.2-linux-amd64 gowitness
chmod +x gowitness
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
dpkg -i google-chrome-stable_current_amd64.deb
echo "done"

echo "Installing dirsearch"
cd ~/tools
git clone https://github.com/maurosoria/dirsearch.git
echo "done"

echo "Installing Httporbe"
go get -u github.com/tomnomnom/httprobe
cp ~/go/bin/httprobe /usr/bin
echo "done"

echo "Installing httpx"
go get -u -v github.com/projectdiscovery/httpx/cmd/httpx
cp ~/go/bin/httpx /usr/bin
echo "done"

echo "Installing Filter-Resolved"
go get github.com/tomnomnom/hacks/filter-resolved
cp ~/go/bin/filter-resolved /usr/bin
echo "done"

echo "Installing gau"
go get -u -v github.com/lc/gau
cp ~/go/bin/gau /usr/bin
echo "done"

echo "Installing wurl"
go get -u github.com/bp0lr/wurl
cp ~/go/bin/wurl /usr/bin
echo "done"

echo "Downloading nuclei templates"
cd /root/tools/ ; git clone https://github.com/projectdiscovery/nuclei-templates.git
echo "done"

echo "Installing nuclei"
go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
cp ~/go/bin/nuclei /usr/bin
echo "done"

echo "Installing waybackurls"
go get github.com/tomnomnom/waybackurls
cp ~/go/bin/waybackurls /usr/bin
echo "done"


echo "Relax and have a coffee !!"
echo -e "\n\n\n\n\n\n\n\n\n\n\nDone! All tools are set up in ~/tools"
ls -la

