
# Ansible Role:  `bodsch.core.ansible_pip`

```yaml
python_pip_modules:
  - name: pytest

  - name: docopt
    version: "0.6.1"

  - name: keyring
    compare_direction: ">="
    version: 4.1.1

  - name: "requests [security]"
    versions:
      - ">= 2.8.1"
      - "== 2.8.*"

  - name: urllib3
    url: "https://github.com/urllib3/urllib3/archive/refs/tags/1.26.8.zip"
```

```yaml
python_pip_build_packages:
  - python3-dev
  - gcc
```
