"""Reproduce a small consumed fixture; never fit or evaluate a new dataset."""
from pathlib import Path
import torch
from ml.schema import read_json, read_jsonl, file_hash, require
from ml.inference import GNNBundle


def verify_fixture(bundle='models/gnn', fixture='fixtures/gnn', device='cpu'):
    root = Path(fixture).resolve()
    manifest = read_json(root / 'manifest.json')
    require(manifest['schema_version'] in ('automud.gnn-fixture.v1','automud.gnn-fixture.v2') and manifest['already_evaluated'], 'Expected consumed reference fixture')
    paths = {}
    for entry in manifest['files']:
        p = (root / entry['path']).resolve()
        require(p.is_relative_to(root), 'Fixture escaped root')
        require(p.stat().st_size == entry['bytes'] and file_hash(p) == entry['sha256'], 'Fixture changed: ' + entry['path'])
        require(entry['path'] not in paths, 'Duplicate fixture input')
        paths[entry['path']] = p
    require(set(paths) == {'graphs.jsonl', 'expected.jsonl'}, 'Unexpected fixture files')
    # Avoid excessive BLAS overhead on tiny household graphs during this test.
    torch.set_num_threads(1)
    model = GNNBundle(bundle, device)
    require(manifest['a_checkpoint'] == model.checkpoint_hashes['a_checkpoint'] and
            manifest['b_checkpoint'] == model.checkpoint_hashes['b_checkpoint'], 'Fixture checkpoint differs')
    expected = {}
    for row in read_jsonl(paths['expected.jsonl']):
        key = row['run_id'], row['window_start'], row['device_id']
        require(key not in expected, 'Duplicate expected record')
        expected[key] = row
    require(len(expected) == manifest['records'], 'Reference record count differs')
    seen = set()
    graphs = 0
    max_error = {'a': 0., 'b': 0.}
    for graph in read_jsonl(paths['graphs.jsonl']):
        graphs += 1
        result = model.score_graph(graph)
        for row in result['devices']:
            key = graph['run_id'], graph['window_start'], row['device_id']
            require(key not in seen and key in expected, 'Unexpected or repeated inference record')
            seen.add(key)
            reference = expected[key]
            require(row['status'] == reference['status'], 'Reference status differs')
            for head, score, flag in (('a', 'behavioral_score', 'behavioral_flag'), ('b', 'link_anomaly', 'link_flag')):
                require(row[flag] is reference[head + '_flag'], 'Reference flag differs: ' + str(key))
                actual, saved = row[score], reference[head]
                require((actual is None) == (saved is None), 'Reference score availability differs')
                if actual is not None:
                    error = abs(actual - saved)
                    max_error[head] = max(max_error[head], error)
                    require(error <= manifest['score_absolute_tolerance'], 'Reference score differs: ' + str(key))
    require(graphs == manifest['graphs'] and seen == expected.keys(), 'Reference population differs')
    model.verify_inputs()
    return dict(status='passed', graphs=graphs, records=len(seen), flag_checks=2 * len(seen),
                max_absolute_score_error=max_error, score_absolute_tolerance=manifest['score_absolute_tolerance'],
                training_invocations=0, new_evaluation_data=False)
