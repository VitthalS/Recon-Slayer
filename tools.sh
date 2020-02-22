#! /bin/bash

sudo apt-get update
sudo apt-get upgrade -y

sudo apt-get install -y git
sudo apt-get install rename
sudo apt-get install -y python3-pip

apt install -y python-pip
sudo apt-get install -y libcurl4-openssl-dev
sudo apt-get install -y libssl-dev
sudo apt-get install -y jq
sudo apt-get install -y ruby-full
sudo apt-get install -y libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev

#Don't forget to set up AWS credentials!
echo "Don't forget to set up AWS credentials!"
apt install -y awscli
echo "Don't forget to set up AWS credentials!"

sudo apt-get install -y build-essential libssl-dev libffi-dev python-dev
sudo apt-get install -y python-setuptools

#create a tools folder in ~/
mkdir ~/tools
cd ~/tools/

echo "Installing Sublist3r"
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r*
pip install -r requirements.txt
cd ~/tools/
echo "done"

echo "Installing censys subdomain finder"
echo "Don't forget to enter API ID and API SECRET"
export CENSYS_API_ID=
export CENSYS_API_SECRET=
git clone https://github.com/christophetd/censys-subdomain-finder.git
cd censys-subdomain-finder
pip install -r requirements.txt
cd ~/tools/
echo "done"

echo "Downloading commonspeak2-wordlist"
git clone https://github.com/assetnote/commonspeak2-wordlists.git
cd ~/tools/
echo "done"

echo "Installing Aquatone"
gem install aquatone
echo "done"

echo "Installing certasset"
git clone https://github.com/arbazkiraak/certasset.git
echo "done"

echo "Installing crt.sh"
git clone https://github.com/tdubs/crt.sh.git
echo "done"


echo -e "\n\n\n\n\n\n\n\n\n\n\nDone! All tools are set up in ~/tools"
ls -la
echo "One last time: don't forget to set up AWS credentials in ~/.aws/!"
