# Ansible Collection - bodsch.certs

Documentation for the collection.



## supported Operating systems

Tested on

* ArchLinux
* Debian based
    - Debian 10 / 11 / 12
    - Ubuntu 20.04 / 22.04

> **RedHat-based systems are no longer officially supported! May work, but does not have to.**


## Requirements & Dependencies

## Included content


### Roles

| Role                                                                       | Build State | Description |
|:---------------------------------------------------------------------------| :---------: | :----       |
| [bodsch.certs.snakeoil](./roles/snakeoil/README.md)                         | [![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/bodsch/ansible-collection-certs/snakeoil.yml?branch=main)][snakeoil] | build a simple snakeoil certificate for a test environment. |

[snakeoil]: https://github.com/bodsch/ansible-collection-certs/actions/workflows/snakeoil.yml

### Modules

| Name                      | Description |
|:--------------------------|:----|




## Installing this collection

You can install the memsource collection with the Ansible Galaxy CLI:

```bash
#> ansible-galaxy collection install bodsch.certs
```

To install directly from GitHub:

```bash
#> ansible-galaxy collection install git@github.com:bodsch/ansible-collection-certs.git
```


You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: bodsch.certs
```

The python module dependencies are not installed by `ansible-galaxy`.  They can
be manually installed using pip:

```bash
pip install -r requirements.txt
```

## Using this collection


You can either call modules by their Fully Qualified Collection Name (FQCN), such as `bodsch.certs.remove_ansible_backups`, 
or you can call modules by their short name if you list the `bodsch.certs` collection in the playbook's `collections` keyword:



```yaml
---
- name: remove older ansible backup files
  bodsch.certs.remove_ansible_backups:
    path: /etc
    holds: 4
```


## Contribution

Please read [Contribution](CONTRIBUTING.md)

## Development,  Branches (Git Tags)

The `master` Branch is my *Working Horse* includes the "latest, hot shit" and can be complete broken!

If you want to use something stable, please use a [Tagged Version](https://github.com/bodsch/ansible-collection-certs/tags)!


## Author

- Bodo Schulz

## License

[Apache](LICENSE)

**FREE SOFTWARE, HELL YEAH!**
