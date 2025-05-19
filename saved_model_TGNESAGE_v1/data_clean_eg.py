import pandas as pd
import os
import joblib
import torch
import numpy as np
from torch.utils.data import Dataset, DataLoader, IterableDataset, TensorDataset


# This is a file using NF_BoT_IoT as validation, only read 200000 records

# load parameters
script_dir = os.path.dirname(os.path.abspath(__file__))

encoder_path = os.path.join(script_dir, "TGN_EGraphSAGE_v1_encoder.pkl")
scaler_path = os.path.join(script_dir, "TGN_EGraphSAGE_v1_scaler.pkl")
time_norm_path = os.path.join(script_dir, "TGN_EGraphSAGE_v1_time_norm.pkl")

encoder = joblib.load(encoder_path)
scaler = joblib.load(scaler_path)
time_norm = joblib.load(time_norm_path)
ts_min, ts_max = time_norm["min"], time_norm["max"]


# read data
# data = pd.read_csv("codes/dataset/BoT_IoT/NF-BoT-IoT-v3.csv", nrows=400000)
data = pd.read_csv("codes/dataset/NF_ToN_IoT/NF-ToN-IoT-v3.csv",skiprows=range(1, 24020260),header=0)
# data = pd.read_csv("codes/dataset/NF_ToN_IoT/NF-ToN-IoT-v3.csv", nrows=14000)
cols = [
    'FLOW_START_MILLISECONDS', # for TGN, following are same with SAGE
    'IPV4_SRC_ADDR',
    'L4_SRC_PORT',
    'IPV4_DST_ADDR',
    'L4_DST_PORT',
    'PROTOCOL',
    'L7_PROTO',
    'IN_BYTES',
    'OUT_BYTES',
    'IN_PKTS',
    'OUT_PKTS',
    'TCP_FLAGS',
    'FLOW_DURATION_MILLISECONDS',
    'Label',
    'Attack',
]
data.sort_values(by="FLOW_START_MILLISECONDS", ascending=True, inplace=True)
data.reset_index(drop=True, inplace=True)

data['IPV4_SRC_ADDR'] = data.IPV4_SRC_ADDR.apply(str)
data['L4_SRC_PORT'] = data.L4_SRC_PORT.apply(str)
data['IPV4_DST_ADDR'] = data.IPV4_DST_ADDR.apply(str)
data['L4_DST_PORT'] = data.L4_DST_PORT.apply(str)

data['IPV4_SRC_ADDR'] = data['IPV4_SRC_ADDR'] + ':' + data['L4_SRC_PORT']
data['IPV4_DST_ADDR'] = data['IPV4_DST_ADDR'] + ':' + data['L4_DST_PORT']

data.drop(columns=['L4_SRC_PORT','L4_DST_PORT'],inplace=True)
data.drop(columns=['Attack'],inplace = True)
data.rename(columns={"Label": "label"},inplace = True)

label = data.label

feature_cols = ['IPV4_SRC_ADDR','IPV4_DST_ADDR','PROTOCOL','L7_PROTO','IN_BYTES',
                'IN_PKTS','OUT_BYTES','OUT_PKTS','TCP_FLAGS','FLOW_DURATION_MILLISECONDS']

X_test  = data[feature_cols]
y_test  = data['label']
ts_test = data['FLOW_START_MILLISECONDS']

ts_test_sec = ts_test/ 1000.0

# ts_test_norm = (ts_test_sec - ts_min)/ (ts_max - ts_min)
# print(ts_test_norm)

# print(ts_test)

# t_test_min, t_test_max = ts_test_sec.min(), ts_test_sec.max()

# t_norm_test = (ts_test_sec - t_test_min) * (ts_max - ts_min)/(t_test_max - t_test_min) + ts_min

# t_norm_test = (t_norm_test - ts_min) / (ts_max - ts_min)

# print(t_norm_test)
cols_to_norm = ['TCP_FLAGS',
                'L7_PROTO',
                'IN_BYTES',
                'OUT_PKTS',
                'OUT_BYTES',
                'PROTOCOL',
                'FLOW_DURATION_MILLISECONDS',
                'IN_PKTS']

## this is the v1 model does NOT use elapse delta on time vector, use min max on test data will
## cause test data leak
ts_test_norm = (ts_test-ts_test.min())/(ts_test.max()-ts_test.min())
t_test_norm  = torch.tensor(ts_test_norm.values, dtype=torch.float32).unsqueeze(1)

ts_test_sec = torch.tensor(ts_test_sec.values, dtype=torch.float32).unsqueeze(1)

X_test = encoder.transform(X_test)
X_test[cols_to_norm] = scaler.transform(X_test[cols_to_norm])
X_test['h'] = X_test[cols_to_norm].values.tolist()

df_edges_test = X_test.copy()
df_edges_test['label'] = y_test

h_arr_test = np.stack(df_edges_test['h'].values)
m_test = torch.tensor(h_arr_test, dtype=torch.float32)

y_test  = torch.tensor(df_edges_test['label'].values,  dtype=torch.long)


class TimeWindowTestDataset(IterableDataset):
    def __init__(self, src_keys, dst_keys, ts_sec, window_sec):
        self.src_keys = src_keys      # List[str]
        self.dst_keys = dst_keys      # List[str]
        self.ts       = ts_sec.squeeze()  # Tensor [N]
        self.window   = window_sec

    def __iter__(self):
        start_time = self.ts[0].item()
        buffer = []
        for i, t in enumerate(self.ts):
            if t.item() < start_time + self.window:
                buffer.append(i)
            else:
                end_time = self.ts[buffer[-1]].item()
                print(f"Yielding window [{start_time:.3f}, {end_time:.3f}] "
                      f" size={len(buffer)}")
                yield buffer
                buffer = [i]
                start_time = t.item()
        if buffer:
            end_time = self.ts[buffer[-1]].item()
            print(f"Yielding window [{start_time:.3f}, {end_time:.3f}] "
                  f" size={len(buffer)}")
            yield buffer

src_test_keys = X_test['IPV4_SRC_ADDR']
dst_test_keys = X_test['IPV4_DST_ADDR']

window_sec = 130  # 5 mins
print(ts_test_sec)
test_ds = TimeWindowTestDataset(src_test_keys, dst_test_keys, ts_test_sec, window_sec)

loader_test = DataLoader(
    test_ds,
    batch_size=None,
    shuffle=False,
    num_workers=0,
)

batch_size = 2000
N = len(src_test_keys)
batches = [list(range(i, min(i+batch_size, N)))
           for i in range(0, N, batch_size)]




__all__ = ["loader_test", "src_test_keys", "dst_test_keys", "m_test", "y_test", "t_test_norm", "batches"]