# python 3 headers, required if submitting to Ansible


from typing import Any

# from ansible.parsing.yaml.objects import AnsibleUnicode
from ansible.utils.display import Display

display = Display()


class FilterModule:
    """Ansible filter plugin for managing and transforming certificate data structures."""

    def filters(self) -> dict[str, Any]:
        """
        Registers available filters for Ansible.

        Returns:
            A dictionary mapping filter names to callable methods.
        """
        return {
            "check_certificates": self.certificates,
            "domain_list": self.domain_list,
            "flatten_domain_list": self.flatten_domain_list,
        }

    def certificates(self, data: dict[str, Any] | None = None) -> list[str]:
        """
        Return a list of domain names for which certificates do not exist.

        Args:
            data: Dictionary returned from a previous Ansible task,
                  typically containing a `results` list with `stat` data.

        Returns:
            A list of domains where the certificate file does not exist.
        """
        # display.v(f" data: ({type(data)}) {data}")

        if not data or "results" not in data:
            display.v("No valid data provided to 'certificates'.")
            return []

        result: list[str] = []
        results = data.get("results", [])

        for entry in results:
            item = entry.get("item", {})
            if not item:
                continue

            domain_name = item.get("domain")
            exists = entry.get("stat", {}).get("exists", False)

            if not exists and domain_name:
                result.append(domain_name)

        display.v(f"Missing certificates: {result}")

        return result

    def domain_list(self, data: list[dict[str, Any]], domain: str) -> list[str]:
        """
        Return a list of all domains and subdomains for a specific domain.

        Args:
            data: List of dictionaries containing `domain` and `subdomains` keys.
            domain: The primary domain to search for.

        Returns:
            A sorted list of unique domains and subdomains.
        """
        domain_list: list[str] = []

        for entry in data:
            if entry.get("domain") == domain:
                subdomains = entry.get("subdomains", [])
                if isinstance(subdomains, str):
                    domain_list = [domain, subdomains]
                elif isinstance(subdomains, list) and subdomains:
                    domain_list = [domain] + subdomains
                else:
                    domain_list = [domain]
                break

        return sorted(set(domain_list))

    def flatten_domain_list(
        self, data: list[dict[str, Any]], with_subdomains: bool = False
    ) -> list[str]:
        """
        Flatten a complex domain list into a single list of domains.

        Args:
            data: List of dictionaries with `domain` and optional `subdomains`.
            with_subdomains: Whether to include subdomains in the flattened list.

        Returns:
            A flattened list of all domains and (optionally) subdomains.
        """
        domains: list[str] = []

        for entry in data:
            domain_name = entry.get("domain")
            if domain_name:
                domains.append(domain_name)

            if with_subdomains:
                subdomains = entry.get("subdomains", [])
                if isinstance(subdomains, str):
                    domains.append(subdomains)
                elif isinstance(subdomains, list):
                    domains.extend(subdomains)

        return sorted(set(domains))
