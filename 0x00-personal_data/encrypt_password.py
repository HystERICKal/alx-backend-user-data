#!/usr/bin/env python3
"""Encrypt passwords."""
import bcrypt


def hash_password(password: str) -> bytes:
    """Encrypt passwords."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Encrypt passwords."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
