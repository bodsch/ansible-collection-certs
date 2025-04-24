
data = [
    {'name': 'pytest'},
    {'name': 'docopt', 'version': '0.6.1'},
    {'name': 'keyring', 'compare_direction': ">=", 'version': '4.1.1'},
    {'name': 'requests [security]', 'versions': ['>= 2.8.1', '== 2.8.*']},
    {'name': 'urllib3', 'url': 'https://github.com/urllib3/urllib3/archive/refs/tags/1.26.8.zip'}
]

result = []

if isinstance(data, list):
    for entry in data:
        print(f"  - {entry}")
        name = entry.get("name")
        compare_direction = entry.get("compare_direction")
        version = entry.get("version", None)
        versions = entry.get("versions", [])
        url = entry.get("url", None)

        print(f"     name               : {type(name)} {name}")
        print(f"     compare_direction  : {type(compare_direction)} {compare_direction}")
        print(f"     version            : {type(version)} {version}")
        print(f"     versions           : {type(versions)} {versions}")
        print(f"     url                : {type(url)} {url}")

        if isinstance(version, str):
            if compare_direction:
                version = f"{compare_direction} {version}"
            else:
                version = f"== {version}"

            result.append(f"{name} {version}")

        elif isinstance(versions, list) and len(versions) > 0:
            versions = ", ".join(versions)
            result.append(f"{name} {versions}")

        elif isinstance(url, str):
            result.append(f"{name} @ {url}")

        # if not version and len(versions) == 0 and not url:
        else:
            result.append(name)
