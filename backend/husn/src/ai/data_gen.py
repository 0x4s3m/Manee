import pandas as pd
import numpy as np
import os
from pathlib import Path

HUSN_DIR = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_PATH = HUSN_DIR / "data" / "synthetic_traffic.csv"


def generate_synthetic_data(n_samples=1500, output_path=DEFAULT_OUTPUT_PATH):
    np.random.seed(42)
    output_path = Path(output_path)

    # Feature names
    features = [
        'flow_duration', 'total_fwd_pkts', 'total_bwd_pkts',
        'fwd_pkt_len_max', 'fwd_pkt_len_min', 'fwd_pkt_len_mean',
        'bwd_pkt_len_max', 'bwd_pkt_len_min', 'bwd_pkt_len_mean',
        'flow_byts_s', 'flow_pkts_s', 'flow_iat_mean', 'flow_iat_max',
        'pkt_len_mean', 'pkt_len_std', 'ack_flag_cnt', 'syn_flag_cnt'
    ]

    data = []
    labels = ['BENIGN', 'DDoS', 'PortScan', 'Brute Force', 'Infiltration', 'Web Attack']

    for _ in range(n_samples):
        label = np.random.choice(labels, p=[0.6, 0.1, 0.1, 0.05, 0.07, 0.08])

        # Base features (BENIGN style)
        row = {
            'flow_duration': np.random.uniform(100, 1000000),
            'total_fwd_pkts': np.random.randint(1, 100),
            'total_bwd_pkts': np.random.randint(1, 100),
            'fwd_pkt_len_max': np.random.uniform(40, 1500),
            'fwd_pkt_len_min': np.random.uniform(0, 40),
            'fwd_pkt_len_mean': np.random.uniform(40, 800),
            'bwd_pkt_len_max': np.random.uniform(40, 1500),
            'bwd_pkt_len_min': np.random.uniform(0, 40),
            'bwd_pkt_len_mean': np.random.uniform(40, 800),
            'flow_byts_s': np.random.uniform(100, 100000),
            'flow_pkts_s': np.random.uniform(0.1, 1000),
            'flow_iat_mean': np.random.uniform(10, 10000),
            'flow_iat_max': np.random.uniform(10, 100000),
            'pkt_len_mean': np.random.uniform(40, 800),
            'pkt_len_std': np.random.uniform(0, 500),
            'ack_flag_cnt': np.random.randint(0, 2),
            'syn_flag_cnt': np.random.randint(0, 2),
            'label': label
        }

        # Adjust features based on attack type
        if label == 'DDoS':
            row['total_fwd_pkts'] *= 10
            row['flow_pkts_s'] *= 20
            row['flow_duration'] *= 0.1
        elif label == 'PortScan':
            row['total_fwd_pkts'] = np.random.randint(1, 3)
            row['flow_iat_mean'] *= 0.1
            row['syn_flag_cnt'] = 1
        elif label == 'Brute Force':
            row['total_fwd_pkts'] = np.random.randint(20, 50)
            row['flow_duration'] *= 2
        elif label == 'Infiltration' or label == 'Web Attack':
            # Complex signatures
            row['pkt_len_mean'] *= 1.5
            row['total_bwd_pkts'] += 50
            row['ack_flag_cnt'] = 1

        data.append(row)

    df = pd.DataFrame(data)
    os.makedirs(output_path.parent, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Synthetic data updated at {output_path}")
    return df

if __name__ == "__main__":
    generate_synthetic_data()
