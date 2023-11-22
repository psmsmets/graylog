import argparse
import pandas as pd

# set arguments
parser = argparse.ArgumentParser(
    prog='lookup_devices.py',
    description='Prepare the devices inventory for graylog lookup tables.'
)                                               
parser.add_argument(
    "--csv-in", "-i", metavar='..', type=str, required=True,
    help="Set the inpput csv file with the devices inventory"
)
parser.add_argument(
    "--csv-out", "-o", metavar='..', type=str, required=False,
    default='lookup_devices.csv',
    help="Set the output csv file for graylog"
)

# get arguments
args = parser.parse_args()

# read csv file
df = pd.read_csv(args.csv_in)

# set column names / fields
sel = [
    'Device ID',
    'Device name',
    'Serial number',
    'Manufacturer',
    'Model',
    'Wi-Fi MAC',
    'EthernetMAC',
    'Primary user display name'
]
last_check = 'Last check-in'

# extract columns extended by last_check
df = df[sel + [last_check]]

# remove empty cells
df = df[(df['Wi-Fi MAC'].notna()) & (df['EthernetMAC'].notna()) & (df['Primary user display name'].notna())]

# sort by last_check
df = df.sort_values(last_check, ascending=False)

# verify unique values by column
# print({c: len(df[c].unique()) for c in ('Device ID', 'Device name', 'Wi-Fi MAC', 'EthernetMAC')})

# remove duplicate values per column/key
for c in ['Device ID', 'Device name', 'Wi-Fi MAC', 'EthernetMAC']:
    df = df.drop_duplicates(subset=[c], keep='first')

# remove last_check column
df = df[sel]

# sort by device name
df = df.sort_values('Device name', ascending=True)

# export to csv
df.to_csv(args.csv_out, index=False)
