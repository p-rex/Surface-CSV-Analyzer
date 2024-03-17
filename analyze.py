import pandas as pd
import tldextract
import yaml
import collections
import sys
import pprint


#=============================================================#
# Classes
#=============================================================#

class SurfaceCSV:
    def __init__(self, csv_type, csv_path, tgt_col_list):
        self.csv_type = csv_type
        self.tgt_col_list = tgt_col_list

        # Declare Instance variables. This class can work without it, but it is for easy to understand.
        self.df=pd.DataFrame()
        self.result_data = {} # Summarized data. The structure is dict in dict

        self.readCSV(csv_path)
        self.analyze()


    def readCSV(self, csv_path):
        try:
            self.df = pd.read_csv(csv_path)
        except FileNotFoundError as e:
            exit(f'Error - {e}')

    def analyze(self):
        for column in self.tgt_col_list:
            if(column == 'Issue ID'): #for 'Issue ID' in issue.csv
                severity_list = ['critical', 'high', 'medium', 'low']
                for severity in severity_list:
                    issue_dict = self.getIssues(severity)
                    str = f'{severity} {column}'
                    self.result_data[str] = issue_dict

            elif(column == 'RootDomain'): # To extract root domain from 'Domains' from domain.csv and service.csv.
                col_dict = self.getRootDomainCnt()
                self.result_data[column] = col_dict


            else:
                col_dict = self.getColCounts(column)
                self.result_data[column] = col_dict


    # Get the value of a specific column (get values vertically)
    # Since there are cases where you want to specify df, create an empty DataFrame and use df.empty to determine it. 
    # I wanted to put "df = self.df" in the argument, but python does not allow it.
    def getSeries(self, column, df=pd.DataFrame()): 
        if(df.empty):
            df = self.df

        item_list = []
        for item in df[column]:
            if(pd.isnull(item)):
                continue
            item_list.append(item)

        return item_list


    # Get number of generic column
    def getColCounts(self, column):
        column_list = self.getSeries(column)
        return dict(collections.Counter(column_list))


    # Get number of root domain
    def getRootDomainCnt(self):
        domain_list = []
        fqdn_list = self.getSeries('Domain')
        for fqdn in fqdn_list:
            ext = tldextract.extract(fqdn)
            domain_list.append(ext.registered_domain)

        return dict(collections.Counter(domain_list))


    # Get issue list
    def getIssues(self, severity):
        df_per_severity = self.df[self.df['Severity'] == severity]
    
        issue_list = self.getSeries('Issue ID', df_per_severity)
        issue_cve_list = []
        issue_non_cve_list = []
        # Separate CVE and Non-CVE for easy to understand.
        for issue in issue_list:
            if(issue.startswith('CVE')):
                issue_cve_list.append(issue)
            else:
                issue_non_cve_list.append(issue)
        
        issue_list = issue_cve_list + issue_non_cve_list
        return dict(collections.Counter(issue_list))

    # This method will support multiple type of output in the future.
    def print(self, type='csv'):
        if(type == 'csv'):
            for column, col_dict in self.result_data.items():
                title = f'# {column} counts - from {self.csv_type}.csv'

                print('\n')
                print(title)
                printDict(col_dict)



#=============================================================#
# functions
#=============================================================#
def printDict(dict):
    for key, value in dict.items():
        print("{0},{1}".format(key, value))


#=============================================================#
# main
#=============================================================#

# Target column
domain_tgt_col_list = ['RootDomain', 'Domain'] #RootDomain has special culculation
service_tgt_col_list = ['RootDomain', 'Protocol', 'Port', 'Platform']
asset_tgt_col_list = ['Hosting Provider', 'Country Name']
issue_tgt_col_list = ['Issue ID'] #Issue ID has special culculation


# Read config file
try:
    with open(sys.argv[1], 'r') as yml:
        config = yaml.safe_load(yml)
except yaml.YAMLError as e:
    exit(f'Error - {e}')


# Analyze each CSV
sc = SurfaceCSV('domain', config['SurfaceCSVPath']['domain'], domain_tgt_col_list)
sc.print()
sc = SurfaceCSV('service', config['SurfaceCSVPath']['service'], service_tgt_col_list)
sc.print()
sc = SurfaceCSV('asset', config['SurfaceCSVPath']['asset'], asset_tgt_col_list)
sc.print()
sc = SurfaceCSV('issue', config['SurfaceCSVPath']['issue'], issue_tgt_col_list)
sc.print()

