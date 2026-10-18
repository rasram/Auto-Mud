"""Frozen E1+Q release identity, actual messages and unchanged service lifecycle."""
import copy
import json
from pathlib import Path
import shutil

import pytest
import torch

from ml.inference import GNNBundle
from ml.live.engine import LiveEngine
from ml.live.examples import example_window
from ml.schema import file_hash, read_jsonl
from ml.supervised.tensors import tensor
from ml.verify_fixture import verify_fixture

ROOT = Path(__file__).resolve().parents[2]
START = 1700000040
E1 = 'supervised-E1Q-20261018'
C = 'supervised-C-20261016'


def rewrite_manifest(path, update=None):
    manifest = json.loads((path / 'manifest.json').read_text())
    if update:
        manifest.update(update)
    for entry in manifest['files']:
        entry.update(bytes=(path / entry['path']).stat().st_size, sha256=file_hash(path / entry['path']))
    (path / 'manifest.json').write_text(json.dumps(manifest))


@pytest.mark.parametrize('folder,version,messages', [('gnn', E1, True), ('gnn-c-20261016', C, False)])
def test_approved_release_and_saved_reference(folder, version, messages):
    torch.set_num_threads(1)
    model = GNNBundle(ROOT / 'models' / folder)
    assert model.bundle_version == version and model.predictor.model.use_graph is messages
    graph = next(read_jsonl(ROOT / 'fixtures' / folder / 'graphs.jsonl'))
    output = model.score_graph(graph)
    assert output['learned_neighbor_messages'] is messages and output['head_c_trained'] is False
    assert verify_fixture(ROOT / 'models' / folder, ROOT / 'fixtures' / folder)['flag_checks'] == 216


@pytest.mark.parametrize('filename', ['thresholds.json', 'normalizer.json', 'flow-profiles.json', 'feature-contract.json'])
@pytest.mark.parametrize('allow_candidate', [False, True])
def test_approved_names_cannot_bypass_frozen_bindings(tmp_path, filename, allow_candidate):
    path = tmp_path / 'bundle'
    shutil.copytree(ROOT / 'models/gnn', path)
    if filename == 'thresholds.json':
        value = json.loads((path / filename).read_text())
        value['A']['value'] = 1.1537269353866577  # Wrong C operating point.
        (path / filename).write_text(json.dumps(value))
    else:
        with (path / filename).open('a') as handle:
            handle.write(' ')  # Semantic equality cannot bypass frozen bytes.
    rewrite_manifest(path)
    with pytest.raises(ValueError, match='Approved supervised checkpoint/assets/operating point differs'):
        GNNBundle(path, allow_candidate=allow_candidate)


@pytest.mark.parametrize('field,value', [('learned_neighbor_messages', False), ('learned_neighbor_messages', 1),
                                       ('head_c_trained', True), ('learning_regime', 'self_supervised')])
def test_false_release_metadata_is_rejected(tmp_path, field, value):
    path = tmp_path / 'bundle'
    shutil.copytree(ROOT / 'models/gnn', path)
    rewrite_manifest(path, {field: value})
    with pytest.raises(ValueError, match='architecture metadata differs'):
        GNNBundle(path)


def test_unknown_version_is_not_production_approved(tmp_path):
    path = tmp_path / 'bundle'
    shutil.copytree(ROOT / 'models/gnn', path)
    rewrite_manifest(path, {'bundle_version': 'unapproved-release'})
    with pytest.raises(ValueError, match='unapproved supervised release'):
        GNNBundle(path)


@pytest.mark.parametrize('flag', [None, 0, 1, 'true'])
def test_checkpoint_architecture_requires_explicit_boolean(tmp_path, flag):
    path = tmp_path / 'bundle'
    shutil.copytree(ROOT / 'models/gnn', path)
    checkpoint = torch.load(path / 'detector.pt', map_location='cpu', weights_only=True)
    checkpoint['use_graph'] = flag
    torch.save(checkpoint, path / 'detector.pt')
    rewrite_manifest(path, {'bundle_version': 'offline-invalid-architecture'})
    with pytest.raises(ValueError, match='explicit boolean use_graph'):
        GNNBundle(path, allow_candidate=True)


def test_e1_really_uses_messages_and_c_does_not():
    graph = next(read_jsonl(ROOT / 'fixtures/gnn/graphs.jsonl'))
    for folder, messages in [('gnn', True), ('gnn-c-20261016', False)]:
        bundle = GNNBundle(ROOT / 'models' / folder)
        data = tensor(graph, graph['prior_graphs'], bundle.predictor.scaler, bundle.profile)
        without_edges = copy.deepcopy(data)
        without_edges.edge_index = data.edge_index[:, :0]
        without_edges.edge_attr = data.edge_attr[:0]
        with torch.inference_mode():
            actual = bundle.predictor.model(data)
            ablated = bundle.predictor.model(without_edges)
        assert torch.equal(actual, ablated) is not messages


def test_strict_cutoffs_are_not_probability_thresholds(monkeypatch):
    bundle = GNNBundle(ROOT / 'models/gnn')
    graph = next(read_jsonl(ROOT / 'fixtures/gnn/graphs.jsonl'))
    cutoffs = torch.tensor([bundle.predictor.thresholds[h]['value'] for h in ('A', 'B')], dtype=torch.float64)
    for values, expected in [(cutoffs, False), (torch.nextafter(cutoffs, torch.full_like(cutoffs, float('inf'))), True)]:
        monkeypatch.setattr(bundle.predictor.model, 'forward', lambda data: values.repeat(len(data.x), 1))
        output = bundle.score_graph(graph)
        checked = [row[key] for row in output['devices'] for key in ('behavioral_flag', 'link_flag') if row[key] is not None]
        assert checked and all(flag is expected for flag in checked)


def test_c_e1_restart_retry_rollback_preserves_history_and_provenance(tmp_path, monkeypatch):
    config = dict(_root=str(ROOT), bundle='models/gnn-c-20261016', allowed_bundle_roots=['models'],
                  state_file=str(tmp_path / 'state.json'), torch_threads=1, device='cpu')
    engine = LiveEngine(config, now=lambda: START + 100000)
    try:
        original, replay = engine.submit(example_window(START))
        assert not replay and original['model']['bundle_version'] == C
        stage = engine.stage('models/gnn')
        disk = (tmp_path / 'state.json').read_bytes()
        with monkeypatch.context() as patch:
            patch.setattr(engine, '_save', lambda payload: (_ for _ in ()).throw(OSError('durable failure')))
            with pytest.raises(OSError, match='durable failure'):
                engine.activate(stage['model']['bundle_id'])
        assert engine.model_info()['bundle_version'] == C
        assert (tmp_path / 'state.json').read_bytes() == disk
        result = engine.activate(stage['model']['bundle_id'])
        assert result['boundary'] == 'between_completed_windows' and result['feature_history_preserved']
        assert not result['model_history_reset_on_next_window']
        assert engine.submit(example_window(START)) == (original, True)
        engine.close()
        engine = LiveEngine(config, now=lambda: START + 100000)
        assert engine.model_info()['bundle_version'] == E1
        current, _ = engine.submit(example_window(START + 60))
        assert current['learned_neighbor_messages'] is True
        assert all(row['history']['prior_windows'] == 1 for row in current['devices'])
        for row in current['devices']:
            assert row['calibration_scope']['a']['value'] == 0.7624336779117584
            assert row['calibration_scope']['b']['value'] == 4.921021908521652
        # New windows must match a fresh E1 forward on the retained raw history.
        graph = next(iter(engine.streams.values()))['last_graph']
        assert current['devices'] == [dict(row, history=current['devices'][i]['history'])
                                      for i, row in enumerate(GNNBundle(ROOT / 'models/gnn').score_graph(graph)['devices'])]
        disk = (tmp_path / 'state.json').read_bytes()
        with monkeypatch.context() as patch:
            patch.setattr(engine, '_save', lambda payload: (_ for _ in ()).throw(OSError('durable failure')))
            with pytest.raises(OSError, match='durable failure'):
                engine.rollback()
        assert engine.model_info()['bundle_version'] == E1 and (tmp_path / 'state.json').read_bytes() == disk
        engine.rollback()
        assert engine.submit(example_window(START + 60)) == (current, True)
        engine.close()
        engine = LiveEngine(config, now=lambda: START + 100000)
        assert engine.model_info()['bundle_version'] == C
        rolled_back, _ = engine.submit(example_window(START + 120))
        assert not rolled_back['learned_neighbor_messages']
        assert all(row['history']['prior_windows'] == 2 for row in rolled_back['devices'])
        for row in rolled_back['devices']:
            assert row['calibration_scope']['a']['value'] == 1.1537269353866577
            assert row['calibration_scope']['b']['value'] == -0.2367836833000183
        assert engine.stage('models/gnn')['status'] == 'staged'
    finally:
        engine.close()
