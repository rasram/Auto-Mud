"""Selected bundle integrity, consumed reproduction and inference boundaries."""
import copy
import json
from pathlib import Path
import shutil
import pytest
import torch
from ml.inference import GNNBundle, VERSION
from ml.schema import read_jsonl
from ml.verify_fixture import verify_fixture

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def model():
    torch.set_num_threads(1)
    return GNNBundle(ROOT / 'models/gnn', 'cpu')


@pytest.fixture
def graph():
    return next(read_jsonl(ROOT / 'fixtures/gnn/graphs.jsonl'))


def test_consumed_reference_outputs_match():
    result = verify_fixture(ROOT / 'models/gnn', ROOT / 'fixtures/gnn', 'cpu')
    assert result['status'] == 'passed'
    assert result['graphs'] == 20 and result['records'] == 394
    assert result['flag_checks'] == 788 and result['training_invocations'] == 0


def test_inference_ignores_reporting_truth_and_preserves_input(model, graph):
    before = copy.deepcopy(graph)
    altered = copy.deepcopy(graph)
    altered['normal'] = not altered.get('normal', False)
    altered['attack_family'] = 'different_report_annotation'
    for node in altered['nodes']:
        for key in ('label', 'behavior_label', 'relationship_label'):
            node[key] = -1
    assert model.score_graph(graph) == model.score_graph(altered)
    assert graph == before


def test_selected_model_has_no_training_or_enforcement(model, graph):
    output = model.score_graph(graph)
    assert output['schema_version'] == VERSION
    assert not output['head_c_trained'] and output['enforcement_action'] is None
    assert all(p.requires_grad is False for p in model.predictor.model.parameters())
    assert all(p.requires_grad is False for p in model.predictor.link.model.parameters())
    assert all(r['compromised_probability'] is None for r in output['devices'])


def test_missing_native_clock_cannot_be_mistaken_for_normal(model, graph):
    graph.pop('source_interval_id')
    with pytest.raises(ValueError, match='Native clock unavailable'):
        model.score_graph(graph)


def test_future_history_is_rejected(model, graph):
    node = next(n for n in graph['nodes'] if n['device_type'] != 'external_service')
    from ml.ab_targets.schema import TEMPORAL_FEATURES
    node['temporal_history'] = [dict(window_start=graph['window_start'],
        features=[0.] * len(TEMPORAL_FEATURES), feature_mask=[False] * len(TEMPORAL_FEATURES))]
    with pytest.raises(ValueError, match='Future history'):
        model.score_graph(graph)


def test_corrupted_bundle_is_rejected(tmp_path):
    target = tmp_path / 'bundle'
    shutil.copytree(ROOT / 'models/gnn', target)
    with (target / 'selected-a.pt').open('ab') as f:
        f.write(b'corrupt')
    with pytest.raises(ValueError, match='Bundle input changed'):
        GNNBundle(target)


def test_manifest_path_escape_is_rejected(tmp_path):
    target = tmp_path / 'bundle'
    target.mkdir()
    manifest = json.loads((ROOT / 'models/gnn/manifest.json').read_text())
    manifest['files'][0]['path'] = '../outside.pt'
    (target / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='escaped root'):
        GNNBundle(target)
