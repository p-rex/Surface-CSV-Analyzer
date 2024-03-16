# Falcon Surface Analyzer

# Usage

1. Export CSV from Surface console.
  
2. Install python modules if needed.
```shell
pip install pandas tldextract
``` 
  
3. Set the csv **fullpath** to environment variables.  
```shell
export SURFACE_CSV_DOMAIN='/aa/aa/xxx-domains-reposify-report.csv' 
export SURFACE_CSV_SERVICE='/aa/aa/xxx-services-reposify-report.csv'
export SURFACE_CSV_ISSUE='/aa/aa/xxx-issues-reposify-report.csv'
export SURFACE_CSV_ASSET='/aa/aa/xxx-assets-reposify-report.csv'
```
  
4. Run the **analyze.py**.
```shell
python analyze.py
```
  
Or you can run the script without saving with the command below.
```shell
curl -s https://github_raw_url/analyze.py | python
```

