# Vendored ML engine

`nids/`, `config/` and `data/sample/` are copied unchanged from the AIML mini project
(https://github.com/NikPihu/AIML_Mini_Project_AIT, commit dc2fbec).

The cloud app imports `nids.detector.Detector` and calls `Detector.predict()`. To pick up model
changes from the AIML repo, re-copy those folders (see `scripts` in the README) and rebuild the image.
The NSL-KDD train/test files are bundled in `data/raw/` (same files as the AIML repo), so builds need no internet download.
