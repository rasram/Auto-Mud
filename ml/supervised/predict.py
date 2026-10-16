"""Frozen direct supervised A/B logits; no fitting or online profile updates."""
import math
import torch
from ml.schema import require, file_hash
from ml.supervised.model import Detector
from ml.supervised.tensors import tensor,Normalizer
from ml.supervised.schema import validate_graph,VERSION
from ml.supervised.graphs import profile_id


class Predictor:
    def __init__(self,checkpoint,normalizer,profile,thresholds,device='cpu'):
        self.device=torch.device(device)
        saved=torch.load(checkpoint,map_location='cpu',weights_only=True)
        require(saved.get('use_graph') is False,'C/E2 adapter requires the no-learned-message architecture')
        self.model=Detector(use_graph=False).to(self.device)
        self.model.load_state_dict(saved['state_dict'],strict=True)
        self.model.eval().requires_grad_(False)
        require(all(bool(torch.isfinite(p).all()) for p in self.model.parameters()),'Nonfinite supervised weights')
        self.scaler=Normalizer(normalizer);self.profile=profile;self.thresholds=thresholds
        self.profile_sha256=profile_id(profile)
        for head in ('A','B'):
            require(math.isfinite(thresholds[head]['value']),'Invalid frozen threshold')
        self.model_id=file_hash(checkpoint)[:16]

    @torch.no_grad()
    def predict(self,graph):
        validate_graph(graph)
        require(all(g.get('flow_profile_sha256')==self.profile_sha256 for g in [graph,*graph['prior_graphs']]),
            'Supervised graph/profile mismatch; rebuild current and prior features with the active frozen profile')
        data=tensor(graph,graph['prior_graphs'],self.scaler,self.profile).to(self.device)
        logits=self.model(data).cpu().tolist()
        origin={e['source'] for e in graph['edges']}
        output=[]
        for i,node in enumerate(graph['nodes']):
            if node['device_type']=='external_service':continue
            available=node['available'] and node['active']
            a,b=logits[i]
            require(math.isfinite(a) and math.isfinite(b),'Nonfinite supervised score')
            scores=dict(a=a if available else None,b=b if available and i in origin else None)
            scope={h.lower():dict(value=self.thresholds[h]['value'],scope='frozen_selection_and_clean_calibration',
                fallback=False,rule='strict score > threshold',score_kind='supervised_raw_logit') for h in ('A','B')}
            output.append(dict(device_id=node['device_id'],device_type=node['device_type'],
                status='ok' if available else 'inactive' if node['available'] else 'unavailable',
                behavioral_score=scores['a'],link_anomaly=scores['b'],
                behavioral_flag=scores['a']>scope['a']['value'] if scores['a'] is not None else None,
                link_flag=scores['b']>scope['b']['value'] if scores['b'] is not None else None,
                component_scores={},calibration_scope=scope,
                unscored_reasons=dict(a=None if scores['a'] is not None else 'inactive_or_unavailable',
                    b=None if scores['b'] is not None else 'inactive_or_unavailable_or_no_initiated_relationship'),
                profile_support=dict(known_device=node['device_id'] in self.profile['external_tx_baseline_by_device']),
                compromised_probability=None))
        return dict(schema_version=VERSION,model_id=self.model_id,run_id=graph['run_id'],window_start=graph['window_start'],
            devices=output,diagnostic=True,head_c_trained=False,
            learning_regime='supervised_direct_detection',learned_neighbor_messages=False)
