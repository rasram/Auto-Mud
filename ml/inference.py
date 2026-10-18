"""Verified selected GNN bundle, independent of training and research datasets."""
from pathlib import Path
import math
import hashlib
import json
import torch
from ml.schema import read_json, file_hash, require
from ml.ab_targets.schema import validate_graph
from ml.ab_targets.predict import Predictor

VERSION = 'automud.gnn-evidence.v1'
A_SHA = '4a233d667d8ec81d21891845c95a27948e5283f105a2ecce93b64d88245e7698'
B_SHA = 'a996d926c634d4d4f3acc326ab748c962ea9ced561472f6c0d2717a9d4c00f7d'

# Production identities bind weights, architecture, assets and operating point.
# Candidate inspection remains an explicit development capability; approved version
# names must always satisfy their pins, even when inspected as candidates.
SUPERVISED_RELEASES = {
    'supervised-C-20261016': dict(
        checkpoint='b89ed3d0496d02a33be5f02a5f5cd8938288943685f9e08d1cac360d149dabd7',
        use_graph=False, cutoffs=(1.1537269353866577, -0.2367836833000183)),
    'supervised-E1Q-20261018': dict(
        checkpoint='bf634ca9c98baf5a6507cf0882009c70630301adeb8b18d0a576751e42b5e5ad',
        use_graph=True, cutoffs=(0.7624336779117584, 4.921021908521652)),
}
SUPERVISED_ASSETS = {
    'normalizer.json': '30c5e6c193d86d17dc436625b8c9bffef22d23b6b78a4649596b274f2048e178',
    'flow-profiles.json': '6fb6b60e80464a98b2e946b59102ffa01addccf89635d4f6451cdf078b4daad5',
    'feature-contract.json': '6cde546183f9e89271f5d4b02477b7d5179374bca5122bded1e3abd68b7ff32f',
}


def equal_artifacts(left, right):
    if isinstance(left, torch.Tensor):
        return isinstance(right, torch.Tensor) and torch.equal(left, right)
    if isinstance(left, dict):
        return isinstance(right, dict) and left.keys() == right.keys() and all(equal_artifacts(v, right[k]) for k, v in left.items())
    if isinstance(left, (list, tuple)):
        return type(left) is type(right) and len(left) == len(right) and all(equal_artifacts(x, y) for x, y in zip(left, right))
    return left == right


def native_clock_ready(graph):
    from ml.clock import native_offsets
    try:
        native_offsets(graph)
        return True
    except (ValueError, TypeError):
        return False


class GNNBundle:
    def __init__(self, bundle='models/gnn', device='cpu', allow_candidate=False):
        self.root = Path(bundle).resolve()
        manifest_bytes = (self.root / 'manifest.json').read_bytes()
        manifest = json.loads(manifest_bytes)
        self.manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
        if manifest.get('schema_version') == 'automud.gnn-bundle.v3':
            self._supervised(manifest,device,allow_candidate)
            return
        self.adapter='v4-residual-native.v1'
        from ml.ab_targets.schema import SCHEMA_HASH as LEGACY_SCHEMA_HASH
        self.graph_schema_hash=LEGACY_SCHEMA_HASH
        candidate = manifest['schema_version'] == 'automud.gnn-bundle.v2'
        require(manifest['schema_version'] == 'automud.gnn-bundle.v1' or candidate and allow_candidate,
                'Unsupported or unapproved bundle manifest')
        if candidate:
            from ml.ab_targets.schema import SCHEMA_HASH
            import re
            require(isinstance(manifest.get('bundle_version'), str) and
                    re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', manifest['bundle_version']) is not None,
                    'Invalid candidate bundle version')
            require(manifest['adapter'] == 'v4-residual-native.v1' and manifest['graph_schema_hash'] == SCHEMA_HASH and
                    manifest['input_schema'] == 'automud.live-window.v1' and manifest['output_schema'] == VERSION,
                    'Candidate external contract or feature adapter differs')
        self.inputs = {}
        for entry in manifest['files']:
            p = (self.root / entry['path']).resolve()
            require(p.is_relative_to(self.root), 'Bundle input escaped root')
            require(p.stat().st_size == entry['bytes'] and file_hash(p) == entry['sha256'], 'Bundle input changed: ' + entry['path'])
            require(entry['path'] not in self.inputs, 'Duplicate bundle input')
            self.inputs[entry['path']] = entry['sha256']
        require(set(self.inputs) == {'selected-a.pt', 'frozen-b.pt', 'results.json'}, 'Unexpected bundle inputs')
        if not candidate:
            require(self.inputs['selected-a.pt'] == A_SHA and self.inputs['frozen-b.pt'] == B_SHA, 'Selected model differs')
        self.predictor = Predictor(self.root / 'selected-a.pt', device)
        artifact = self.predictor.artifact
        require(artifact['normalizer'].get('clock_mode') == 'native_source', 'Native-source clock normalizer required')
        if not candidate:
            require(artifact['feature_mask_probability'] == .30 and artifact['precision_recipe'] == 'prior_context_residual' and
                    artifact['context_calibration_tail'] == .05, 'Selected operating point differs')
        require(artifact['residual_reference']['mode'] == 'top3_normalized_absolute_residual_max_components',
                'Unsupported residual scoring adapter')
        original_b = torch.load(self.root / 'frozen-b.pt', map_location='cpu', weights_only=True)
        require(equal_artifacts(artifact['frozen_link_checkpoint'], original_b), 'Embedded B differs from original frozen B')
        from ml.live.contracts import digest
        self.bundle_id = digest(manifest)
        self.bundle_version = manifest.get('bundle_version', 'selected-new2-20261011')
        for model in (self.predictor.model, self.predictor.link.model):
            model.eval()
            for parameter in model.parameters():
                require(bool(torch.isfinite(parameter).all()), 'Nonfinite model weights')
                parameter.requires_grad_(False)
        self.verify_inputs()

    def verify_inputs(self):
        require(file_hash(self.root / 'manifest.json') == self.manifest_sha, 'Bundle manifest changed during inference')
        require(all(file_hash(self.root / p) == h for p, h in self.inputs.items()), 'Bundle changed during inference')

    @property
    def checkpoint_hashes(self):
        if self.adapter=='supervised-direct.v1':
            return dict(a_checkpoint=self.inputs['detector.pt'],b_checkpoint=self.inputs['detector.pt'])
        return dict(a_checkpoint=self.inputs['selected-a.pt'],b_checkpoint=self.inputs['frozen-b.pt'])

    def _supervised(self,manifest,device,allow_candidate):
        from ml.supervised.schema import SCHEMA_HASH, FEATURES, LOG_FEATURES
        from ml.supervised.predict import Predictor as SupervisedPredictor
        from ml.live.contracts import digest
        import re
        require(manifest.get('adapter')=='supervised-direct.v1' and manifest.get('graph_schema_hash')==SCHEMA_HASH and
            manifest.get('input_schema')=='automud.live-window.v1' and manifest.get('output_schema')==VERSION,
            'Supervised bundle contract or adapter differs')
        require(re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',manifest.get('bundle_version','')) is not None,'Invalid bundle version')
        self.adapter=manifest['adapter'];self.graph_schema_hash=SCHEMA_HASH;self.inputs={}
        for entry in manifest['files']:
            path=(self.root/entry['path']).resolve()
            require(path.is_relative_to(self.root),'Bundle input escaped root')
            require(entry['path'] not in self.inputs,'Duplicate bundle input')
            require(path.stat().st_size==entry['bytes'] and file_hash(path)==entry['sha256'],'Bundle input changed: '+entry['path'])
            self.inputs[entry['path']]=entry['sha256']
        require(set(self.inputs)=={'detector.pt','normalizer.json','flow-profiles.json','thresholds.json','feature-contract.json','results.json'},'Unexpected supervised bundle inputs')
        self.profile=read_json(self.root/'flow-profiles.json');normalizer=read_json(self.root/'normalizer.json')
        thresholds=read_json(self.root/'thresholds.json');features=read_json(self.root/'feature-contract.json')
        require(features['features']==list(FEATURES) and features['log_feature_indices']==list(LOG_FEATURES) and
            features['history_windows']==15,'Frozen supervised feature projection differs')
        require(self.profile.get('frozen') is True,'Frozen clean profile required')
        require(isinstance(self.profile.get('groups'),dict) and
            isinstance(self.profile.get('external_tx_baseline_by_device'),dict),'Invalid frozen profile structure')
        require(all(isinstance(v,(int,float)) and not isinstance(v,bool) and math.isfinite(v) and v>=0
            for v in self.profile['external_tx_baseline_by_device'].values()),'Invalid frozen profile baseline')
        for group in self.profile['groups'].values():
            counts=group.get('counts')
            require(isinstance(counts,dict) and isinstance(group.get('total'),(int,float)) and
                math.isfinite(group['total']) and group['total']>=0 and
                all(isinstance(v,(int,float)) and not isinstance(v,bool) and math.isfinite(v) and v>=0 for v in counts.values()) and
                sum(counts.values())==group['total'],'Invalid frozen profile counts')
        require('global' in normalizer['stats'],'Missing global normalizer fallback')
        for stat in normalizer['stats'].values():
            require(len(stat['mean'])==len(stat['std'])==61 and all(math.isfinite(v) for v in stat['mean']) and
                all(math.isfinite(v) and v>0 for v in stat['std']),'Invalid frozen normalizer')
        release=SUPERVISED_RELEASES.get(manifest['bundle_version'])
        require(release is not None or allow_candidate,'Unsupported or unapproved supervised release')
        if release is not None:
            require(self.inputs['detector.pt']==release['checkpoint'] and
                all(self.inputs[name]==sha for name,sha in SUPERVISED_ASSETS.items()) and
                tuple(thresholds[h]['value'] for h in ('A','B'))==release['cutoffs'],
                'Approved supervised checkpoint/assets/operating point differs')
        self.predictor=SupervisedPredictor(self.root/'detector.pt',normalizer,self.profile,thresholds,device)
        require(manifest.get('learning_regime')=='supervised_direct_detection' and
            manifest.get('head_c_trained') is False and
            manifest.get('learned_neighbor_messages') is self.predictor.model.use_graph,
            'Supervised architecture metadata differs')
        if release is not None:
            require(self.predictor.model.use_graph is release['use_graph'],'Approved supervised architecture differs')
        self.bundle_id=digest(manifest);self.bundle_version=manifest['bundle_version'];self.verify_inputs()

    @torch.no_grad()
    def score_graph(self, graph):
        if self.adapter=='supervised-direct.v1':
            require(native_clock_ready(graph),'Native clock unavailable; supply observed UTC or captured-source provenance')
            result=self.predictor.predict(graph)
            result.update(schema_version=VERSION,input_schema_version=graph['schema_version'],session_id=graph['session_id'],
                window_end=graph['window_start']+60,provenance=self.checkpoint_hashes,enforcement_action=None)
            return result
        validate_graph(graph)
        require(native_clock_ready(graph), 'Native clock unavailable; live wrapper must report unscored input')
        result = self.predictor.predict(graph)
        for row in result['devices']:
            require(all(row[k] is None or math.isfinite(row[k]) for k in ('behavioral_score', 'link_anomaly')),
                    'Nonfinite model score')
            require(all(math.isfinite(t['value']) for t in row['calibration_scope'].values()), 'Nonfinite saved threshold')
        result.update(schema_version=VERSION, input_schema_version=graph['schema_version'],
                      session_id=graph['session_id'], window_end=graph['window_start'] + 60,
                      provenance=dict(a_checkpoint=self.inputs['selected-a.pt'], b_checkpoint=self.inputs['frozen-b.pt']), enforcement_action=None)
        return result
