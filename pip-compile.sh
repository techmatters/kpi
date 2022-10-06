#!/bin/bash
for in_file in dependencies/pip/*.in
do
    # pass any arguments to pip-compile
    # useful for switches like `--upgrade-package`
    pip-compile "$@" "$in_file"
done
for out_file in dependencies/pip/*.txt
do
    # Workaround for https://github.com/jazzband/pip-tools/issues/1326
    echo "backports-zoneinfo==0.2.1; python_version < '3.9'" >> "$out_file"
done
