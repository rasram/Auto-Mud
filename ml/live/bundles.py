"""Portable bundle export and controlled deployment compatibility checks."""
import json
from pathlib import Path
import re
import shutil
from ml.schema import require, file_hash
from ml.ab_targets.schema import SCHEMA_HASH
from ml.inference import GNNBundle, VERSION


def export_bundle(checkpoint, frozen_b, out, version, results=None):
    root = Path(out).resolve()
    require(not root.exists(), 'Bundle destination already exists; use a new version directory')
    require(re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', version) is not None, 'Invalid bundle version')
    if Path(checkpoint).is_dir():
        source=GNNBundle(checkpoint,'cpu',allow_candidate=True)
        require(source.adapter=='supervised-direct.v1','Directory export expects a supervised bundle')
        root.mkdir(parents=True)
        for name in source.inputs:shutil.copy2(source.root/name,root/name)
        if results:shutil.copy2(results,root/'results.json')
        manifest=json.loads((source.root/'manifest.json').read_text())
        manifest['bundle_version']=version
        manifest['files']=[dict(path=name,bytes=(root/name).stat().st_size,sha256=file_hash(root/name)) for name in source.inputs]
        (root/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        model=GNNBundle(root,'cpu',allow_candidate=True);model.verify_inputs()
        return dict(bundle_version=version,bundle_id=model.bundle_id,path=str(root),verified=True,
                    training_invocations=0,accuracy_validated=False)
    require(frozen_b is not None,'For supervised releases export a complete evaluated bundle directory, including its own frozen assets')
    require(Path(checkpoint).is_file() and Path(frozen_b).is_file(), 'Missing model input')
    root.mkdir(parents=True)
    shutil.copy2(checkpoint, root / 'selected-a.pt')
    shutil.copy2(frozen_b, root / 'frozen-b.pt')
    result = json.loads(Path(results).read_text()) if results else dict(bundle_version=version, accuracy_not_supplied=True,
        purpose='Deployment candidate; installation/forward checks do not establish accuracy')
    (root / 'results.json').write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    files = [dict(path=p.name, bytes=p.stat().st_size, sha256=file_hash(p))
             for p in (root / 'selected-a.pt', root / 'frozen-b.pt', root / 'results.json')]
    manifest = dict(schema_version='automud.gnn-bundle.v2', bundle_version=version, adapter='v4-residual-native.v1',
                    graph_schema_hash=SCHEMA_HASH, input_schema='automud.live-window.v1', output_schema=VERSION, files=files)
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    try:
        model = GNNBundle(root, 'cpu', allow_candidate=True)
        model.verify_inputs()
    except Exception as error:
        (root / 'EXPORT_FAILED.txt').write_text(str(error))
        raise
    return dict(bundle_version=version, bundle_id=model.bundle_id, path=str(root), verified=True,
                training_invocations=0, accuracy_validated=False)
