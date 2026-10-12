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

    @torch.no_grad()
    def score_graph(self, graph):
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
