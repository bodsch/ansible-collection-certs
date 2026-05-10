# -*- coding: utf-8 -*-
# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""Custom exceptions for step-ca module utilities."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class StepCAError(Exception):
    """Base exception for all step-ca module utility errors."""


class StepCAAuthError(StepCAError):
    """Raised when admin token generation or authentication fails."""


class StepCAAPIError(StepCAError):
    """Raised when the step-ca admin API returns an error response."""

    def __init__(self, message, status_code=None, payload=None):
        super(StepCAAPIError, self).__init__(message)
        self.status_code = status_code
        self.payload = payload


class StepCAConfigError(StepCAError):
    """Raised when ca.json cannot be parsed or required entries are missing."""
