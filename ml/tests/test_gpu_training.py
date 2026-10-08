import copy
import random
import pytest
import torch

from ml.smoke import fixtures
from ml.dataset_prep.catalog import load_partition
from ml.dataset_prep.tensors import Normalizer, to_pyg
from ml.model.graphsage import Detector
from ml.training.runtime import stage1_loss, stage1_batch_loss, known_relationships, resolve_training_device


def examples(tmp_path):
    catalog = fixtures(tmp_path)
    graphs = load_partition(catalog, "stage1_train")[:8]
    graphs[1] = copy.deepcopy(graphs[1])
    graphs[1]["edges"] = []
    scaler = Normalizer().fit(graphs)
    return graphs, [to_pyg(g, scaler) for g in graphs], known_relationships(graphs)


def test_batched_losses_and_gradients_preserve_per_graph_objective(tmp_path):
    graphs, tensors, known = examples(tmp_path)
    torch.manual_seed(7)
    original = Detector().eval()
    batched = copy.deepcopy(original)
    rng = random.Random(8)
    losses = [stage1_loss(original, g, d, known, rng) for g, d in zip(graphs, tensors)]
    expected = sum(a + b for a, b, _ in losses) / len(losses)
    expected.backward()
    rec, link, _ = stage1_batch_loss(batched, graphs, tensors, known, random.Random(8))
    actual = (rec + link).mean()
    actual.backward()
    assert torch.allclose(expected, actual, rtol=1e-5, atol=1e-6)
    for (name, p), (_, q) in zip(original.named_parameters(), batched.named_parameters()):
        if p.grad is not None:
            assert torch.allclose(p.grad, q.grad, rtol=2e-4, atol=2e-6), name


@pytest.mark.skipif(not torch.cuda.is_available(), reason="CUDA unavailable")
def test_cuda_graphsage_forward_backward_and_optimizer(tmp_path):
    graphs, tensors, known = examples(tmp_path)
    model = Detector().to(resolve_training_device("cuda"))
    before = model.layer1.lin_l.weight.detach().clone()
    optimizer = torch.optim.Adam(model.parameters(), lr=.001)
    rec, link, _ = stage1_batch_loss(model, graphs, tensors, known, random.Random(8))
    loss = (rec + link).mean()
    assert loss.device.type == "cuda" and torch.isfinite(loss)
    loss.backward()
    optimizer.step()
    torch.cuda.synchronize()
    assert not torch.equal(before, model.layer1.lin_l.weight)
