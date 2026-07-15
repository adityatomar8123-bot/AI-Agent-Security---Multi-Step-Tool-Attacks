"""Stockfish Transposition Table (TT) & Zobrist Hashing.

Translates position key generation (Zobrist hashing) and entry bounds cache
from Stockfish's C++ representation (tt.cpp and tt.h).
"""

from __future__ import annotations

import random
from typing import Final, NamedTuple
from stockfish_python.types import Color, Piece, Square
from stockfish_python.movegen import Move
from stockfish_python.position import Position

# TT entry flags
BOUND_EXACT: Final[int] = 0
BOUND_ALPHA: Final[int] = 1  # Upper bound
BOUND_BETA: Final[int] = 2   # Lower bound


class TTEntry(NamedTuple):
    """Represents a cached search state in the Transposition Table."""

    zobrist_key: int
    depth: int
    score: float
    flag: int
    best_move: Move | None


class Zobrist:
    """Computes standard Zobrist hashing for chess board configurations."""

    def __init__(self) -> None:
        # Initialize random keys for all (square, piece) pairs
        # Piece indices range 0-14.
        self.piece_keys: list[list[int]] = [[random.getrandbits(64) for _ in range(15)] for _ in range(64)]
        self.side_key: int = random.getrandbits(64)
        self.castling_keys: list[int] = [random.getrandbits(64) for _ in range(16)]
        self.ep_keys: list[int] = [random.getrandbits(64) for _ in range(65)]  # Index 64 is SQ_NONE

    def hash(self, pos: Position) -> int:
        """Compute and return the 64-bit Zobrist hash key of the position."""
        h = 0
        for sq in range(64):
            p = pos.board[sq]
            if p != Piece.NO_PIECE:
                h ^= self.piece_keys[sq][p]

        if pos.side_to_move == Color.BLACK:
            h ^= self.side_key

        h ^= self.castling_keys[pos.castling_rights]
        h ^= self.ep_keys[pos.ep_square]
        return h


# Static Zobrist instance
ZOBRIST: Final[Zobrist] = Zobrist()


class TranspositionTable:
    """State cache that maps Zobrist keys to search evaluations (Transposition Table)."""

    def __init__(self, size_limit: int = 100_000) -> None:
        self.table: dict[int, TTEntry] = {}
        self.size_limit: int = size_limit

    def clear(self) -> None:
        """Clear all entries in the cache."""
        self.table.clear()

    def store(self, zobrist_key: int, depth: int, score: float, flag: int, best_move: Move | None) -> None:
        """Store a search result in the table."""
        # Simple replacement strategy: if full, clear table to prevent leaks
        if len(self.table) >= self.size_limit:
            self.table.clear()
        self.table[zobrist_key] = TTEntry(zobrist_key, depth, score, flag, best_move)

    def probe(self, zobrist_key: int) -> TTEntry | None:
        """Probe the table to retrieve cached evaluation."""
        return self.table.get(zobrist_key)
