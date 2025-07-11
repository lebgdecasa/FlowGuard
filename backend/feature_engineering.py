import pandas as pd

def add_history_bucket(df):
    PURE_MALICIOUS = {'I', 'DTT'}
    SUSPICIOUS_COMBOS = {'ShAdDaFf','ShAdDafF','ShADadfF','ShADafF','ShADar','ShAdDaFr','ShAdDfFr','ShAdDaft','ShADr','ShADdfFa'}
    PURE_BENIGN = {'D','Dd','R'}
    def bucket_history(val):
        if val == 'S': return 'majority_S'
        elif val in PURE_MALICIOUS: return 'pure_malicious'
        elif val in SUSPICIOUS_COMBOS: return 'known_suspicious_combos'
        elif val in PURE_BENIGN: return 'pure_benign'
        else: return 'rare_mixed'
    df['history_bucket'] = df['history'].apply(bucket_history)
    df.drop(columns=['history'], inplace=True)
    return df

def add_duration_bucket(df):
    def bucket_duration(x):
        if x < 0.001: return 'tiny'
        elif 2.9 <= x <= 3.2: return 'typical'
        elif 3.2 < x < 50: return 'long'
        elif x >= 50: return 'very_long'
        else: return 'other'
    df['duration_bucket'] = df['duration'].apply(bucket_duration)
    df.drop(columns=['duration'], inplace=True)
    return df
