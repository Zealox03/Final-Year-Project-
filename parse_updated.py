import json
import csv
from datetime import datetime

# Define CSV headers (added ddos_flag)
headers = [
    'timestamp', 'transaction_id', 'remote_address', 'remote_port', 'local_address', 'local_port',
    'request_line', 'host_header', 'user_agent', 'accept_header', 'response_protocol', 'response_status',
    'last_modified', 'etag', 'content_length', 'content_type', 'message', 'error_message',
    'stopwatch_p1', 'stopwatch_p2', 'stopwatch_p3', 'stopwatch_p4', 'stopwatch_p5',
    'stopwatch_sr', 'stopwatch_sw', 'stopwatch_l', 'stopwatch_gc', 'producer', 'server', 'engine_mode',
    'ddos_flag'
]

# Function to parse timestamp to a standard format
def parse_timestamp(time_str):
    try:
        # Parse the timestamp and convert to ISO format
        dt = datetime.strptime(time_str.split(' +')[0], '%d/%b/%Y:%H:%M:%S.%f')
        return dt.isoformat()
    except ValueError:
        return time_str

# Function to check for DDoS-related messages
def is_ddos_message(message):
    ddos_indicators = ['DDoS detected', 'attack-ddos']
    return any(indicator.lower() in message.lower() for indicator in ddos_indicators)

# Function to flatten log entry into a CSV row
def flatten_log_entry(entry):
    row = {}
    # Transaction details
    transaction = entry.get('transaction', {})
    row['timestamp'] = parse_timestamp(transaction.get('time', ''))
    row['transaction_id'] = transaction.get('transaction_id', '')
    row['remote_address'] = transaction.get('remote_address', '')
    row['remote_port'] = transaction.get('remote_port', '')
    row['local_address'] = transaction.get('local_address', '')
    row['local_port'] = transaction.get('local_port', '')

    # Request details
    request = entry.get('request', {})
    row['request_line'] = request.get('request_line', '')
    headers = request.get('headers', {})
    row['host_header'] = headers.get('Host', '')
    row['user_agent'] = headers.get('User-Agent', '')
    row['accept_header'] = headers.get('Accept', '')

    # Response details
    response = entry.get('response', {})
    row['response_protocol'] = response.get('protocol', '')
    row['response_status'] = response.get('status', '')
    resp_headers = response.get('headers', {})
    row['last_modified'] = resp_headers.get('Last-Modified', '')
    row['etag'] = resp_headers.get('ETag', '')
    row['content_length'] = resp_headers.get('Content-Length', '')
    row['content_type'] = resp_headers.get('Content-Type', '')

    # Audit data
    audit_data = entry.get('audit_data', {})
    messages = audit_data.get('messages', [])
    error_messages = audit_data.get('error_messages', [])
    row['message'] = '; '.join(messages)
    row['error_message'] = '; '.join(error_messages)
    
    # Check for DDoS indicators
    row['ddos_flag'] = 'Yes' if (any(is_ddos_message(msg) for msg in messages) or 
                                any(is_ddos_message(err) for err in error_messages)) else 'No'
    
    # Stopwatch
    stopwatch = audit_data.get('stopwatch', {})
    row['stopwatch_p1'] = stopwatch.get('p1', '')
    row['stopwatch_p2'] = stopwatch.get('p2', '')
    row['stopwatch_p3'] = stopwatch.get('p3', '')
    row['stopwatch_p4'] = stopwatch.get('p4', '')
    row['stopwatch_p5'] = stopwatch.get('p5', '')
    row['stopwatch_sr'] = stopwatch.get('sr', '')
    row['stopwatch_sw'] = stopwatch.get('sw', '')
    row['stopwatch_l'] = stopwatch.get('l', '')
    row['stopwatch_gc'] = stopwatch.get('gc', '')

    # Other audit data
    row['producer'] = '; '.join(audit_data.get('producer', []))
    row['server'] = audit_data.get('server', '')
    row['engine_mode'] = audit_data.get('engine_mode', '')

    # Print warning for DDoS detection
    if row['ddos_flag'] == 'Yes':
        print(f"DDoS detected in transaction {row['transaction_id']} from {row['remote_address']} "
              f"at {row['timestamp']}: {row['message']}")

    return row

# Read and parse the modsec_audit.log file
log_file = 'modsec_audit_2.log'
log_data = []

try:
    with open(log_file, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                log_entry = json.loads(line)
                log_data.append(log_entry)
            except json.JSONDecodeError as e:
                print(f"Error parsing JSON line: {e}")
                continue
except FileNotFoundError:
    print(f"Error: The file '{log_file}' was not found.")
    exit(1)
except Exception as e:
    print(f"Error reading file: {e}")
    exit(1)

# Write to CSV
output_file = 'modsec_audit_2_complete.csv'
try:
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        
        for entry in log_data:
            row = flatten_log_entry(entry)
            writer.writerow(row)
    print(f"CSV file '{output_file}' has been generated successfully.")
except Exception as e:
    print(f"Error writing CSV file: {e}")
    exit(1)