"""Self-contained composite checkpoint inference; no fitting at prediction time."""
from ml.schema import file_hash,require
from ml.ab_targets.schema import VERSION,SCHEMA_HASH
from ml.ab_targets.runtime import load
from ml.ab_targets.scoring import FrozenLink,behavior_scores
from ml.ab_targets.calibration import threshold_info,context


class Predictor:
    def __init__(self,checkpoint,device='auto'):
        import torch
        metadata=torch.load(checkpoint,map_location='cpu',weights_only=True)
        require(not metadata.get('flow_protocol_version'), 'This package supports the selected v4 checkpoint only')
        self.model,self.scaler,self.artifact=load(checkpoint,device)
        require(all(k in self.artifact for k in ('threshold_a','threshold_b','residual_reference','frozen_link_checkpoint')),
                'Composite checkpoint must have completed clean calibration')
        self.link=FrozenLink(device=device,artifact=self.artifact['frozen_link_checkpoint'])
        self.model_id=file_hash(checkpoint)[:16]

    def predict(self,graph):
        a=behavior_scores(self.model,self.scaler,graph,self.artifact['residual_reference']); b=self.link.scores(graph)
        output=[]
        for index,node in enumerate(graph['nodes']):
            available=node['available'] and node['active']; observable=context(graph,index)
            ta=threshold_info(self.artifact['threshold_a'],node,observable)
            tb=threshold_info(self.artifact['threshold_b'],node,observable)
            score_a=a.get(index,{}).get('score') if available else None
            score_b=b.get(index) if available else None
            output.append(dict(device_id=node['device_id'],device_type=node['device_type'],
                status='ok' if available else 'inactive' if node['available'] else 'unavailable',
                behavioral_score=score_a,link_anomaly=score_b,
                behavioral_flag=score_a>ta['value'] if score_a is not None else None,
                link_flag=score_b>tb['value'] if score_b is not None else None,
                component_scores=a.get(index,{}).get('components',{}),calibration_scope=dict(a=ta,b=tb),
                unscored_reasons=dict(a=None if score_a is not None else 'inactive_or_unavailable_or_no_valid_features',
                                     b=None if score_b is not None else 'inactive_or_unavailable_or_no_initiated_relationship'),
                compromised_probability=None))
        return dict(schema_version=VERSION,schema_hash=SCHEMA_HASH,model_id=self.model_id,run_id=graph['run_id'],
                    window_start=graph['window_start'],devices=output,diagnostic=True,head_c_trained=False)
