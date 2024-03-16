# Falcon Surface Analyzer

# Usage

1. Export CSV from Surface console.

2. install python module if needed.
```shell
pip install pandas tldextract
``` 
 

3. Set your csv filepath to environment variables.  
I recommend you to use *full path*.
```shell
export SURFACE_CSV_DOMAIN='/aa/aa/xxx-domains-reposify-report.csv' 
export SURFACE_CSV_SERVICE='/aa/aa/xxx-services-reposify-report.csv'
export SURFACE_CSV_ISSUE='/aa/aa/xxx-issues-reposify-report.csv'
export SURFACE_CSV_ASSET='/aa/aa/xxx-assets-reposify-report.csv'
```

4. run the script
```shell
python analyze.py
```
  
You can run this script without saving with the command below.
```shell
https://raw_url/ | python
```

