# Runtime telemetry and tensor utilities

`extract.py` applies the project Zeek policy to PCAPs. `tensors.py` supplies the
saved v3 normalization/tensor conversion required by frozen B. `sequences.py`
provides traffic-sequence utilities still used by the shared Mininet generator.
The selected model never fits normalization or thresholds at inference time.
Full training/evaluation datasets are not needed for live operation.
