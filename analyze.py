import pandas as pd
import tldextract
import collections
import os
import pprint


#############################################
### Classes

class SurfaceCSV:

    def __init__(self, csv_path):
        self.df = pd.read_csv(csv_path)

    #特定カラムの値を取得（CSVを縦に取得）
    #dfを指定したい場合があるため、空のDataFrameを作成し、df.emptyで判断する。本当は引数にdf = self.dfを入れたいが、こうしないとエラーになる。
    def getSeries(self, col, df=pd.DataFrame()): 
        if(df.empty):
            df = self.df

        item_list = []
        for item in df[col]:
            if(pd.isnull(item)):
                continue
            item_list.append(item)

        return item_list


    #Root Domainの数を取得
    def getRootDomainCnt(self):
        domain_list = []
        fqdn_list = self.getSeries('Domain')
        for fqdn in fqdn_list:
            ext = tldextract.extract(fqdn)
            domain_list.append(ext.registered_domain)

        return dict(collections.Counter(domain_list))


    #一般的に項目の数を取得
    def getColCounts(self, col):
        col_list = self.getSeries(col)
        return dict(collections.Counter(col_list))



    # Issueの一覧を取得
    def getIssues(self, severity):
        df_per_severity = self.df[self.df['Severity'] == severity]
    
        issue_list = self.getSeries('Issue ID', df_per_severity)
        issue_cve_list = []
        issue_non_cve_list = []
        #CVEとNon-CVEの出力を分離する。分かりやすくするため。
        for issue in issue_list:
            if(issue.startswith('CVE')):
                issue_cve_list.append(issue)
            else:
                issue_non_cve_list.append(issue)
        
        issue_list = issue_cve_list + issue_non_cve_list
        return dict(collections.Counter(issue_list))



class PrintFormat:
    def __init__(self, title, dict):
        self.title = title
        self.dict = dict

    def print2Console(self):
        print('\n')
        print(self.title)
        printDict(self.dict)



#############################################
### functions

def printDict(dict):
    for key, value in dict.items():
        print("{0},{1}".format(key, value))



#############################################
### main

# Set environment variables
csv_domain = os.getenv('SURFACE_CSV_DOMAIN')
csv_service = os.getenv('SURFACE_CSV_SERVICE')
csv_issue = os.getenv('SURFACE_CSV_ISSUE')
csv_asset = os.getenv('SURFACE_CSV_ASSET')

#=== domains.csv ======
sc_domain = SurfaceCSV(csv_domain)

# Counts Domain from domain
domain_dict = sc_domain.getRootDomainCnt()
pf = PrintFormat('# Domain counts - with unofficial perimeter', domain_dict)
pf.print2Console()

# Counts FQDN
col_dict = sc_domain.getColCounts('Domain')
pf = PrintFormat('# FQDN counts - with unofficial perimeter', col_dict)
pf.print2Console()


#=== services.csv ======
sc_issue = SurfaceCSV(csv_service)

### Counts Domain from Service
domain_dict = sc_issue.getRootDomainCnt()
pf = PrintFormat('# Domain counts - from service', domain_dict)
pf.print2Console()

### Counts columns from Service
column_list = ['Protocol', 'Port', 'Platform']
for column in column_list:
    col_dict = sc_issue.getColCounts(column)
    pf = PrintFormat('# ' + column + ' counts - from service', col_dict)
    pf.print2Console()


#=== issues.csv ======
# Counts Issues
sc_issue = SurfaceCSV(csv_issue)
secerity_list = ['critical', 'high', 'medium', 'low']
for severity in secerity_list:
    issue_dict = sc_issue.getIssues(severity)
    pf = PrintFormat('# Issue counts - ' + severity, issue_dict)
    pf.print2Console()




#=== assets.csv ======
sc_asset = SurfaceCSV(csv_asset)

### Counts Hosting Provider from asset
column_list = ['Hosting Provider', 'Country Name']
for column in column_list:
    col_dict = sc_issue.getColCounts(column)
    pf = PrintFormat('# ' + column + ' counts - from asset', col_dict)
    pf.print2Console()



