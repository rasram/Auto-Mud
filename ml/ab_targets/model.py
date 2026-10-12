import torch
from torch import nn
from torch_geometric.nn import SAGEConv
from ml.ab_targets.schema import FEATURES, X_NAMES, MASK_OFFSET, TEMPORAL_FEATURES


class BehaviorSAGE(nn.Module):
    """A spatial GraphSAGE decoder and optional strictly causal forecaster."""
    def __init__(self,aggregation='mean',mode='hybrid',hidden=64,embedding=16):
        super().__init__()
        if aggregation not in ('mean','mean_max') or mode not in ('spatial','hybrid'): raise ValueError('Invalid A candidate')
        self.config=dict(aggregation=aggregation,mode=mode,hidden=hidden,embedding=embedding)
        self.mode=mode
        aggr=['mean','max'] if aggregation=='mean_max' else 'mean'
        self.conv1=SAGEConv(len(X_NAMES),hidden,aggr=aggr); self.conv2=SAGEConv(hidden,embedding,aggr=aggr)
        self.self1=nn.Linear(len(X_NAMES),hidden); self.self2=nn.Linear(hidden,embedding)
        self.gates=nn.Parameter(torch.full((2,),-2.)); self.norm=nn.LayerNorm(hidden); self.dropout=nn.Dropout(.1)
        self.spatial_decoder=nn.Sequential(nn.Linear(embedding,hidden),nn.ReLU(),nn.Linear(hidden,len(FEATURES)))
        if mode=='hybrid':
            self.gru=nn.GRU(2*len(TEMPORAL_FEATURES),embedding,batch_first=True)
            self.context=nn.Linear(MASK_OFFSET-len(FEATURES),embedding)
            self.forecast_decoder=nn.Sequential(nn.Linear(embedding,hidden),nn.ReLU(),nn.Linear(hidden,len(FEATURES)))

    def forward(self,data):
        x=torch.cat((data.x[:,:len(FEATURES)].clamp(-8,8),data.x[:,len(FEATURES):]),dim=1)
        gates=torch.sigmoid(self.gates)
        h=self.dropout(torch.relu(self.norm((1-gates[0])*self.self1(x)+gates[0]*self.conv1(x,data.edge_index))))
        h=(1-gates[1])*self.self2(h)+gates[1]*self.conv2(h,data.edge_index)
        result={'spatial':self.spatial_decoder(h)}
        if self.mode=='hybrid':
            _,history=self.gru(data.temporal_history.clamp(-8,8))
            metadata=data.x[:,len(FEATURES):MASK_OFFSET].clone(); metadata[:,2]=0
            result['temporal']=self.forecast_decoder(history[-1]+self.context(metadata))
        return result
