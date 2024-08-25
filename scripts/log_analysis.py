import argparse
import glob
import re
import pandas as pd

def parse_logs(log_dir):
    log_files = glob.glob(f"{log_dir}/*.log")
    data = []
    for file in log_files:
        with open(file, 'r') as f:
            for line in f:
                timestamp = extract_timestamp(line)
                ip = extract_ip(line)
                event = extract_event(line)
                if timestamp and ip and event:
                    data.append({'timestamp': timestamp, 'ip': ip, 'event': event})
    return pd.DataFrame(data)

def extract_timestamp(line):
    match = re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', line)
    return match.group() if match else None

def extract_ip(line):
    match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
    return match.group() if match else None

def extract_event(line):
    if 'failed login' in line.lower():
        return 'Failed Login'
    elif 'successful login' in line.lower():
        return 'Successful Login'
    else:
        return 'Other'

def analyze_events(df):
    failed_logins = df[df['event'] == 'Failed Login']
    suspicious_ips = failed_logins['ip'].value_counts().head(5)
    return suspicious_ips

def main(log_dir):
    df = parse_logs(log_dir)
    suspicious_ips = analyze_events(df)
    print("Top 5 Suspicious IPs based on failed login attempts:")
    print(suspicious_ips)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Log Analysis Tool')
    parser.add_argument('--log-dir', required=True, help='Directory containing log files')
    args = parser.parse_args()
    main(args.log_dir)
