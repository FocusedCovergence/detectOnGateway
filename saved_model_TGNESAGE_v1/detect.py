from TGN_EGraph_Sage_model import  model, reset_state, device
from data_clean_eg import src_test_keys, dst_test_keys, m_test, y_test, t_test_norm, batches
from data_clean_eg import loader_test, src_test_keys, dst_test_keys, m_test, y_test, t_test_norm
import pandas as pd
import torch
import time
from sklearn.metrics import accuracy_score, precision_score, f1_score, confusion_matrix

print(torch.__version__)
print(torch.version.cuda)

model.eval()
reset_state()

results = []
with torch.no_grad():
    for batch_i, idxs in enumerate(loader_test, 1):

        src_idx_list = []
        dst_idx_list = []
        for j in idxs:
            sk = src_test_keys[j]
            if sk not in model.id_map:
                model.id_map[sk] = model.next_id
                model.next_id += 1
            src_idx_list.append(model.id_map[sk])
            dk = dst_test_keys[j]
            if dk not in model.id_map:
                model.id_map[dk] = model.next_id
                model.next_id += 1
            dst_idx_list.append(model.id_map[dk])

        


        max_idx = max(max(src_idx_list), max(dst_idx_list))


        cap = model.mem.num_embeddings
        print(f"[Batch {batch_i}] mem size = {cap}, max requested idx = {max_idx}")


        if max_idx >= cap:
            raise RuntimeError(
                f"Index {max_idx} >= mem capacity {cap} (batch {batch_i})"
            )

        src_idx = torch.tensor(src_idx_list, dtype=torch.long, device=device)
        dst_idx = torch.tensor(dst_idx_list, dtype=torch.long, device=device)


        feats_batch  = m_test[idxs].to(device)        # [B, F]
        labels_batch = y_test[idxs].to(device)        # [B]
        ts_norm_batch= t_test_norm[idxs].to(device)   # [B,1]

        t0 = time.time()
        logits = model(src_idx, dst_idx, feats_batch, ts_norm_batch)
        dt = time.time() - t0

        probs  = torch.softmax(logits, dim=1).cpu().numpy()
        preds  = probs.argmax(axis=1)
        true   = labels_batch.cpu().numpy()

        batch_acc  = accuracy_score(true, preds)
        cm        = confusion_matrix(true, preds, labels=[0,1])
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        precision  = tp / (tp + fp) if (tp + fp) > 0 else 0.0

        results.append({
            "batch":    batch_i,
            "size":     len(idxs),
            "time_s":   dt,
            "accuracy": batch_acc,
            "precision":precision,
            "fpr":      fpr,
            "cm":       cm,
        })
        print(f"Batch {batch_i:03d} | size={len(idxs)} | time={dt:.3f}s"
      f" | acc={batch_acc:.3f} | prec={precision:.3f} | fpr={fpr:.3f}")


import numpy as np
tn=fp=fn=tp=0
for r in results:
    tcm = r["cm"].ravel()
    tn+=tcm[0]; fp+=tcm[1]; fn+=tcm[2]; tp+=tcm[3]
total = tn+fp+fn+tp
cm_overall = np.array([[tn, fp],
                       [fn, tp]])
overall_acc = (tn+tp)/total
overall_fpr = fp/(fp+tn)
overall_f1 = 2*tp/(2*tp+fp+fn)
overall_precision  = tp / (tp + fp) if (tp + fp) > 0 else 0.0
print(f"\nOverall  | acc={overall_acc:.3f} | fpr={overall_fpr:.3f} | f1={overall_f1:.3f}")
print("Overall confusion matrix:")
print(cm_overall)
print(f"\nOverall metrics | acc = {overall_acc:.3f} | precision = {overall_precision:.3f} | fpr = {overall_fpr:.3f} | f1 = {overall_f1:.3f}")

print("Batch 1 CM:\n", results[2]["cm"])