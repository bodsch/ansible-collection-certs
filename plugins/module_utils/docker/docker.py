#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# (c) 2020-2022, Bodo Schulz <bodo@boone-schulz.de>
# BSD 2-clause (see LICENSE or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function
import os
# import json

import docker


class DockerClient():
    """
    """
    module = None

    def __init__(self, module, socket="/var/run/docker.sock"):
        """
        """
        self.module = module

        self.docker_status = False
        self.docker_socket = socket

    def client(self):
        """
        """

        # TODO
        # with broken ~/.docker/daemon.json will this fail!
        try:
            if os.path.exists(self.docker_socket):
                # self.module.log("use docker.sock")
                self.docker_client = docker.DockerClient(base_url=f"unix://{self.docker_socket}")
            else:
                self.docker_client = docker.from_env()

            self.docker_status = self.docker_client.ping()
        except docker.errors.APIError as e:
            self.module.log(
                msg=f" exception: {e}"
            )
        except Exception as e:
            self.module.log(
                msg=f" exception: {e}"
            )

        if not self.docker_status:
            return dict(
                changed=False,
                failed=True,
                msg="no running docker found"
            )
