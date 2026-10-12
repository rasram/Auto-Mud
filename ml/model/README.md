# Frozen Head B architecture

`graphsage.py` defines the architecture needed to load the original frozen B
checkpoint. Selected Head A is defined in `ml/ab_targets/model.py`.
Retaining B's v3 architecture and schema is necessary for loading the selected
composite checkpoint; these files are not obsolete model artifacts.
