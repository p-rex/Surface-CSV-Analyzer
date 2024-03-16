import pandas as pd
import tldextract
import collections
import os
import pprint


#=============================================================#
# Classes
#=============================================================#

class SurfaceCSV:

    def __init__(self, csv_path):
        try:
            self.df = pd.read_csv(csv_path)
        except FileNotFoundError as e:
            exit(f'Error - {e}')

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


    #一般的な項目の数を取得
    def getColCounts(self, col):
        col_list = self.getSeries(col)
        return dict(collections.Counter(col_list))


    #Root Domainの数を取得
    def getRootDomainCnt(self):
        domain_list = []
        fqdn_list = self.getSeries('Domain')
        for fqdn in fqdn_list:
            ext = tldextract.extract(fqdn)
            domain_list.append(ext.registered_domain)

        return dict(collections.Counter(domain_list))


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



# This class will support multiple output format.
class OutputFormat:
    def __init__(self, title, dict):
        self.title = title
        self.dict = dict

    def print2Console(self):
        print('\n')
        print(self.title)
        printDict(self.dict)



class AnalyzeRouter:
    def __init__(self, csv_type, tgt_col_list, output_fmt):
        self.csv_type = csv_type
        self.tgt_col_list = tgt_col_list
        self.output_fmt = output_fmt
        self.routing()
    
    def routing(self):
        if(self.csv_type == 'domain'):
            sc = SurfaceCSV(csv_domain)
        elif(self.csv_type == 'service'):
            sc = SurfaceCSV(csv_service)
        elif(self.csv_type == 'asset'):
            sc = SurfaceCSV(csv_asset)
        elif(self.csv_type == 'issue'):
            sc = SurfaceCSV(csv_issue)

        for column in self.tgt_col_list:
            if(column == 'Issue ID'): #for 'Issue ID' in issue.csv
                severity_list = ['critical', 'high', 'medium', 'low']
                for severity in severity_list:
                    issue_dict = sc.getIssues(severity)
                    self.output(f'{severity} {column}', issue_dict)
                continue

            elif(column == 'RootDomain'): # To extract root domain from 'Domains' from domain.csv and service.csv.
                col_dict = sc.getRootDomainCnt()

            else:
                col_dict = sc.getColCounts(column)
            
            self.output(column, col_dict)



    def output(self, column, col_dict):
        if(self.output_fmt == 'console_csv'):
            of = OutputFormat(f'# {column} counts - from {self.csv_type}.csv', col_dict)
            of.print2Console()



#=============================================================#
# functions
#=============================================================#
def printDict(dict):
    for key, value in dict.items():
        print("{0},{1}".format(key, value))


#=============================================================#
# main
#=============================================================#
# config
domain_tgt_col_list = ['RootDomain', 'Domain'] #RootDomain has special culculation
service_tgt_col_list = ['RootDomain', 'Protocol', 'Port', 'Platform']
asset_tgt_col_list = ['Hosting Provider', 'Country Name']
issue_tgt_col_list = ['Issue ID'] #Issue ID has special culculation
output_fmt = 'console_csv'


# Get environment variables
try:
    csv_domain = os.environ['SURFACE_CSV_DOMAIN']
    csv_service = os.environ['SURFACE_CSV_SERVICE']
    csv_asset = os.environ['SURFACE_CSV_ASSET']
    csv_issue = os.environ['SURFACE_CSV_ISSUE']
except KeyError as e:
    exit(f'Error - Please specify CSV file path in environment variable: {e}')


# Analyze
AnalyzeRouter('domain', domain_tgt_col_list, output_fmt)
AnalyzeRouter('service', service_tgt_col_list, output_fmt)
AnalyzeRouter('asset', asset_tgt_col_list, output_fmt)
AnalyzeRouter('issue', issue_tgt_col_list, output_fmt)

