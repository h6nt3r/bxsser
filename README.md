## Installation
##### If you don't have installed google-chrome browser on you system then do it.
```
mkdir -p --mode=777 bxsser
cd bxsser
echo "google-chrome===================================="
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt --fix-broken install -y
sudo apt install ./google-chrome-stable*.deb -y
cd
sudo rm -rf bxsser
```
```
echo "bxsser===================================="
cd /opt/ && sudo git clone https://github.com/h6nt3r/bxsser.git && cd bxsser/
sudo chmod +x ./*
sudo pip3 install -r requirements.txt --break-system-packages
cd
sudo ln -sf /opt/bxsser/bxsser.py /usr/local/bin/bxsser
bxsser -h
```
## Usage
#### Stdio mode
```
echo "http://testphp.vulnweb.com/listproducts.php?cat=ok" | bxsser -p payloads.txt
```
#### Single url
```
bxsser -u "http://testphp.vulnweb.com/listproducts.php?cat=ok" -p payloads.txt
```
#### File scanning
```
bxsser -f urls.txt -p payloads.txt
```
