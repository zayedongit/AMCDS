import csv
import random
import os

def generate_synthetic_data(num_samples=1000):
    data = []
    
    # Generate benign requests
    for _ in range(int(num_samples * 0.7)): # 70% benign
        url_length = random.randint(15, 80)
        special_char_count = random.randint(0, 3)
        path_entropy = random.uniform(2.0, 4.0)
        user_agent_length = random.randint(60, 120)
        has_anomalous_headers = 0
        request_body_size = random.randint(0, 2000)
        label = 0 # 0 for benign
        data.append([url_length, special_char_count, path_entropy, user_agent_length, has_anomalous_headers, request_body_size, label])
        
    # Generate malicious requests
    for _ in range(int(num_samples * 0.3)): # 30% malicious
        # Malicious might have longer URLs (SQLi, buffer overflow), more special chars, higher entropy, etc.
        attack_type = random.choice(['sqli', 'xss', 'bot'])
        if attack_type == 'sqli':
            url_length = random.randint(60, 200)
            special_char_count = random.randint(5, 25)
            path_entropy = random.uniform(3.5, 4.5)
            user_agent_length = random.randint(60, 120)
            has_anomalous_headers = random.choice([0, 1])
            request_body_size = random.randint(0, 500)
        elif attack_type == 'xss':
            url_length = random.randint(50, 150)
            special_char_count = random.randint(4, 15)
            path_entropy = random.uniform(3.0, 4.5)
            user_agent_length = random.randint(60, 120)
            has_anomalous_headers = 0
            request_body_size = random.randint(50, 1000)
        else: # bot/automated tool
            url_length = random.randint(15, 60)
            special_char_count = random.randint(0, 3)
            path_entropy = random.uniform(2.0, 3.5)
            user_agent_length = random.randint(0, 30) # Very short or missing UA
            has_anomalous_headers = 1
            request_body_size = random.randint(0, 100)
            
        label = 1 # 1 for malicious
        data.append([url_length, special_char_count, path_entropy, user_agent_length, has_anomalous_headers, request_body_size, label])
        
    # Shuffle the data
    random.shuffle(data)
    
    # Write to CSV
    os.makedirs('../data', exist_ok=True)
    with open('../data/sample_requests.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['url_length', 'special_char_count', 'path_entropy', 'user_agent_length', 'has_anomalous_headers', 'request_body_size', 'is_malicious'])
        writer.writerows(data)
        
    print(f"Generated {len(data)} synthetic requests in ../data/sample_requests.csv")

if __name__ == '__main__':
    generate_synthetic_data()
