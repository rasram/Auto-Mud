"""Original E1/C architecture: own-device encoder/GRU and two supervised heads.

E1 enables directed incoming/outgoing messages. C retains the same parameter
keys with use_graph=False, allowing exact loading of either frozen checkpoint.
"""
import torch
from torch import nn
from .tensors import INPUT_WIDTH, BASE_WIDTH, EDGE_WIDTH, HISTORY


def aggregate(messages, index, n):
    sums = messages.new_zeros((n,messages.shape[1])).index_add(0,index,messages)
    counts = messages.new_zeros(n).index_add(0,index,torch.ones_like(index,dtype=messages.dtype))
    return torch.cat((sums,sums/counts[:,None].clamp(min=1),counts[:,None]),1)


class Detector(nn.Module):
    def __init__(self,use_graph=True):
        super().__init__()
        self.use_graph=use_graph
        self.self_encoder=nn.Sequential(nn.Linear(INPUT_WIDTH,64),nn.ReLU())
        self.incoming=nn.Sequential(nn.Linear(64+EDGE_WIDTH,64),nn.ReLU())
        self.outgoing=nn.Sequential(nn.Linear(64+EDGE_WIDTH,64),nn.ReLU())
        self.in_reduce=nn.Sequential(nn.Linear(129,64),nn.ReLU())
        self.out_reduce=nn.Sequential(nn.Linear(129,64),nn.ReLU())
        self.gru=nn.GRU(BASE_WIDTH+1,32,batch_first=True)
        self.head_a=nn.Sequential(nn.Linear(64*3+32,32),nn.ReLU(),nn.Linear(32,1))
        self.head_b=nn.Sequential(nn.Linear(64*3+32,32),nn.ReLU(),nn.Linear(32,1))

    def forward(self,data):
        own=self.self_encoder(data.x)
        incoming,outgoing=torch.zeros_like(own),torch.zeros_like(own)
        if self.use_graph and data.edge_index.shape[1]:
            u,v=data.edge_index
            incoming=self.in_reduce(aggregate(self.incoming(torch.cat((own[u],data.edge_attr),1)),v,len(own)))
            outgoing=self.out_reduce(aggregate(self.outgoing(torch.cat((own[v],data.edge_attr),1)),u,len(own)))
        state=own.new_zeros((1,len(own),32))
        for step in range(HISTORY):
            valid=data.history_available[:,step]
            hx=torch.cat((data.history_x[:,step],valid[:,None]),1)[:,None]
            _,state=self.gru(hx,state)
            state=state*valid[None,:,None]
        joined=torch.cat((own,incoming,outgoing,state[0]),1)
        return torch.cat((self.head_a(joined),self.head_b(joined)),1)
