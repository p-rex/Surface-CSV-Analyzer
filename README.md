# Falcon Surface Analyzer

# Usage

1. Export CSV from the Surface console.
  
2. Install python modules if needed.
```shell
pip install pandas tldextract pyyaml
``` 
  
3. Download **config.yml** and specify the csv fullpath in the yaml. You can change the filename of **config.yml**.  
  
4. Run the **analyze.py** with config.yml as an argument.
  
You can run the script without saving it by the command below.
```shell
curl -s https://raw.githubusercontent.com/p-rex/Surface-CSV-Analyzer/main/analyze.py | python - config.yml
```
  
I recommend you to save the result as CSV.
```shell
curl -s https://raw.githubusercontent.com/p-rex/Surface-CSV-Analyzer/main/analyze.py | python - config.yml > result.csv
```
