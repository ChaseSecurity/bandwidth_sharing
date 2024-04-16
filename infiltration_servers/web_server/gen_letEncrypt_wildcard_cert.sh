#!/bin/bash
# this will output txt records to add to your zone file
acme.sh --issue -d mpaas.shop -d *.mpaas.shop --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please
# once add to your zone file, run this again
acme.sh --issue -d mpaas.shop -d *.mpaas.shop --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please --renew
