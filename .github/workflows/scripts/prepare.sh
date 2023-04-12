#!/usr/bin/env bash
#

# yq -i ".version = \"${1}\" | .appVersion style=\"double\" | .appVersion = \"${1}\"" chart/Chart.yaml
# helm package chart
sed -i "s|__version__.*|__version__ = \"${1}\"|" CrowdStrikeSpotlight2HumioMainV2.py