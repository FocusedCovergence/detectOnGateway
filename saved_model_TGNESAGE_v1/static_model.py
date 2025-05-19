import torch
import torch.nn as nn
from torch_geometric.nn import MessagePassing
import torch.nn.functional as F
# import joblib
import os

class SAGELayer(MessagePassing):
    def __init__(self, ndim_in, edims, ndim_out, activation):
        super(SAGELayer, self).__init__(aggr='mean')  # mean aggregation = fn.mean
        self.W_msg = nn.Linear(ndim_in + edims, ndim_out)     # Eq4
        self.W_apply = nn.Linear(ndim_in + ndim_out, ndim_out) # Eq5
        self.activation = activation

    def forward(self, x, edge_index, edge_attr):
        # x: [num_nodes, ndim_in]
        # edge_attr: [num_edges, edims]
        return self.propagate(edge_index, x=x, edge_attr=edge_attr)

    def message(self, x_j, edge_attr):
        # x_j: source node features for each edge
        # edge_attr: edge features
        return self.W_msg(torch.cat([x_j, edge_attr], dim=-1))  # Eq4

    def update(self, aggr_out, x):
        # aggr_out: aggregated message per node
        h_new = self.W_apply(torch.cat([x, aggr_out], dim=-1))  # Eq5
        return self.activation(h_new)


class SAGE(nn.Module):
    def __init__(self, ndim_in, ndim_out, edim, activation, dropout):
        super(SAGE, self).__init__()
        self.layers = nn.ModuleList()
        self.layers.append(SAGELayer(ndim_in, edim, 128, activation))
        self.layers.append(SAGELayer(128, edim, ndim_out, activation))
        self.dropout = nn.Dropout(p=dropout)

    def forward(self, x, edge_index, edge_attr):
        for i, layer in enumerate(self.layers):
            if i != 0:
                x = self.dropout(x)
            x = layer(x, edge_index, edge_attr)
        return x
    
    
class MLPPredictor(nn.Module):
    def __init__(self, in_features, out_classes):
        super().__init__()
        self.W = nn.Linear(in_features * 2, out_classes)

    def forward(self, x, edge_index):
        # x: node embeddings, shape [num_nodes, in_features]
        # edge_index: [2, num_edges]
        src, dst = edge_index  # src: from, dst: to

        h_u = x[src]  # shape [num_edges, in_features]
        h_v = x[dst]  # shape [num_edges, in_features]

        edge_input = torch.cat([h_u, h_v], dim=1)  # [num_edges, in_features*2]
        return self.W(edge_input)
    
class Model(nn.Module):
    def __init__(self, ndim_in, ndim_out, edim, activation, dropout):
        super().__init__()
        self.gnn = SAGE(ndim_in, ndim_out, edim, activation, dropout)
        self.pred = MLPPredictor(ndim_out, 2)

    def forward(self, data):
        node_embeddings = self.gnn(data.x, data.edge_index, data.edge_attr)
        edge_logits = self.pred(node_embeddings, data.edge_index)
        return edge_logits
    

# script_dir = os.path.dirname(os.path.abspath(__file__))

# static_model = os.path.join(script_dir, "../static_model/static_ESAGEmodel_weights.pth")


model = Model(
    ndim_in=8,
    ndim_out=128,    
    edim=8,
    activation=F.relu,
    dropout=0.2
)
import os
print(os.getcwd())
# get the trained dict
state_dict = torch.load("codes/static_model/static_ESAGEmodel_weights.pth", map_location="cpu",weights_only=True)
model.load_state_dict(state_dict)

__all__ = ["model"]