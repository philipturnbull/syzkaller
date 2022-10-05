set -ex
./generate-config.py "$(pwd)/.." "$(nproc)" > my.cfg
sudo ./bin/syz-manager -debug -vv 10 -config my.cfg 2>&1 | tee debug-log
