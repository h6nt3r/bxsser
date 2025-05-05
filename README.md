## Installation
```
mkdir -p --mode=777 bxsser
cd bxsser
echo "google-chrome===================================="
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt --fix-broken install -y
sudo apt install ./google-chrome-stable*.deb -y
cd
sudo rm -rf bxsser
echo "bxsser===================================="
cd /opt/ && sudo git clone https://github.com/mrok716/bxsser.git && cd bxsser/
sudo chmod +x ./*
sudo pip3 install -r requirements.txt
cd
sudo ln -sf /opt/bxsser/bxsser.py /usr/local/bin/bxsser
bxsser -h
```
