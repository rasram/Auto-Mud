"""Unchanged selected A residual scoring and frozen B relationship scoring."""
from collections import defaultdict
import numpy as np
import torch
from ml.schema import require
from ml.ab_targets.runtime import load_legacy as load_v3
from ml.dataset_prep.tensors import to_pyg as old_tensor
from ml.ab_targets.schema import FEATURES, project_v3
from ml.ab_targets.tensors import to_pyg

class FrozenLink:
    def __init__(self,checkpoint=None,device='cpu',artifact=None):
        if artifact is None:
            self.model,self.scaler,self.artifact=load_v3(checkpoint,device)
        else:
            from ml.schema import SCHEMA_HASH as legacy_hash
            from ml.model.graphsage import Detector
            from ml.dataset_prep.tensors import Normalizer
            from ml.ab_targets.runtime import resolve_runtime_device
            require(artifact['schema_hash']==legacy_hash,'Frozen link schema mismatch')
            self.artifact=artifact; self.model=Detector(**artifact['model_config'])
            self.model.load_state_dict(artifact['model_state']); self.model.to(resolve_runtime_device(device))
            self.scaler=Normalizer(artifact['normalizer'])
        require(self.model.revision=='robust','Frozen Head B requires initiated-relationship semantics')
        self.model.eval()
        for parameter in self.model.parameters(): parameter.requires_grad_(False)

    @torch.no_grad()
    def scores(self,graph):
        old=project_v3(graph)
        data=old_tensor(old,self.scaler).to(next(self.model.parameters()).device)
        logits=self.model.score_pairs(data.x,data.edge_index,data.positive_pairs)
        grouped=defaultdict(list)
        for (u,v),score in zip(data.positive_pairs.t().tolist(),(-logits.double()).tolist()): grouped[u].append(score)
        return {i:max(values) for i,values in grouped.items()}



@torch.no_grad()
def residuals(model,scaler,graph):
    cached=getattr(model,'_residual_cache',None)
    if cached is not None:
        key=(graph['run_id'],graph['window_start'])
        require(key in cached,'Residual cache lacks requested fitting/development graph')
        return cached[key]
    data=to_pyg(graph,scaler).to(next(model.parameters()).device)
    return {name:(value-data.target).abs().cpu().numpy() for name,value in model(data).items()}



def aggregate_residual(errors,mask,scale,k=3):
    values=np.asarray(errors)[np.asarray(mask,bool)]/np.asarray(scale)[np.asarray(mask,bool)]
    if not len(values): return None
    require(np.isfinite(values).all(),'Invalid residual score')
    return float(np.sort(values)[-min(k,len(values)):].mean())



def behavior_scores(model,scaler,graph,reference):
    from ml.ab_targets.context_scoring import reference_group
    errors=residuals(model,scaler,graph); output={}
    for i,node in enumerate(graph['nodes']):
        if not(node['active'] and node['available']): continue
        group=reference_group(reference,graph,i)
        components={name:aggregate_residual(values[i],node['feature_mask'],group[name]['scale'],reference['top_k'])
                    for name,values in errors.items()}
        if reference.get('component_normalization'):
            normalization=reference['component_normalization']
            scales=normalization['groups'].get('device:'+node['device_id'],normalization['groups']['global'])
            components={name:score/scales[name] if score is not None else None for name,score in components.items()}
        valid=[value for value in components.values() if value is not None]
        output[i]=dict(score=max(valid) if valid else None,components=components)
    return output

