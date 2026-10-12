"""Frozen checkpoint loading only; no optimizer, fitting or dataset imports."""
import torch
from ml.schema import require, SCHEMA_HASH as LEGACY_SCHEMA_HASH
from ml.ab_targets.schema import SCHEMA_HASH
from ml.ab_targets.model import BehaviorSAGE
from ml.ab_targets.tensors import Normalizer
from ml.model.graphsage import Detector
from ml.dataset_prep.tensors import Normalizer as LegacyNormalizer

def resolve_runtime_device(device="auto"):
    selected = torch.device("cuda" if torch.cuda.is_available() else "cpu") if device == "auto" else torch.device(device)
    require(selected.type in ("cpu", "cuda"), "Supported devices are cpu or cuda")
    if selected.type == "cuda":
        require(torch.cuda.is_available(), "CUDA requested but unavailable; install CUDA-enabled PyTorch")
        probe = torch.ones(2, device=selected)
        require(float((probe * probe).sum()) == 2, "CUDA compute probe failed")
        torch.cuda.synchronize(selected)
    return selected



def load(path,device='cpu'):
    artifact=torch.load(path,map_location='cpu',weights_only=True)
    require(artifact['schema_hash']==SCHEMA_HASH,'Head A checkpoint schema mismatch')
    model=BehaviorSAGE(**artifact['model_config']); model.load_state_dict(artifact['model_state'])
    model.to(resolve_runtime_device(device)).eval()
    return model,Normalizer(artifact['normalizer']),artifact



def load_legacy(path, device="cpu"):
    artifact = torch.load(path, map_location="cpu", weights_only=True)
    require(artifact["schema_hash"] == LEGACY_SCHEMA_HASH, "Checkpoint feature schema mismatch")
    model = Detector(**artifact["model_config"])
    model.load_state_dict(artifact["model_state"])
    model.to(resolve_runtime_device(device))
    model.eval()
    return model, LegacyNormalizer(artifact["normalizer"]), artifact

