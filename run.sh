set -ex
./generate-config.py "$(pwd)/.." "$(nproc)" > my.cfg
sudo ./bin/syz-manager -config my.cfg 2>&1 | tee debug-log
