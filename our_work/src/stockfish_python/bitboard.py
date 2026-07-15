"""Stockfish Bitboard Representation and Operations.

Translates 64-bit bitboard math, bit shifts, population counters,
and static attack lookups from Stockfish's C++ codebase (bitboard.h and attacks.cpp).
"""

from __future__ import annotations

from typing import Final
from stockfish_python.types import Square, make_square, file_of, rank_of

# Bitboard representation mask for 64-bit integers.
MASK64: Final[int] = 0xFFFFFFFFFFFFFFFF


def count_bits(bb: int) -> int:
    """Return the popcount (number of set bits) of a bitboard."""
    return bin(bb & MASK64).count("1")


def lsb(bb: int) -> Square:
    """Return the index (Square) of the least significant set bit."""
    val = bb & MASK64
    if val == 0:
        return Square.SQ_NONE
    return Square((val & -val).bit_length() - 1)


def pop_lsb(bb: int) -> tuple[Square, int]:
    """Remove and return the least significant set bit and the updated bitboard."""
    sq = lsb(bb)
    if sq == Square.SQ_NONE:
        return Square.SQ_NONE, 0
    # Clear the LSB.
    return sq, (bb & (bb - 1)) & MASK64


# Initialize lookup tables
PAWN_ATTACKS: Final[dict[int, list[int]]] = {0: [0] * 64, 1: [0] * 64}  # 0: White, 1: Black
KNIGHT_ATTACKS: Final[list[int]] = [0] * 64
KING_ATTACKS: Final[list[int]] = [0] * 64

# Directions for moves
KNIGHT_DELTAS = [(-2, -1), (-2, 1), (-1, -2), (-1, 2), (1, -2), (1, 2), (2, -1), (2, 1)]
KING_DELTAS = [(-1, -1), (-1, 0), (-1, 1), (0, -1), (0, 1), (1, -1), (1, 0), (1, 1)]


def _init_static_attacks() -> None:
    for s in range(64):
        file, rank = file_of(Square(s)), rank_of(Square(s))

        # 1. Pawn Attacks
        # White pawns attack up-left (+7) and up-right (+9)
        w_att = 0
        if file > 0 and rank < 7:
            w_att |= 1 << (s + 7)
        if file < 7 and rank < 7:
            w_att |= 1 << (s + 9)
        PAWN_ATTACKS[0][s] = w_att & MASK64

        # Black pawns attack down-left (-9) and down-right (-7)
        b_att = 0
        if file > 0 and rank > 0:
            b_att |= 1 << (s - 9)
        if file < 7 and rank > 0:
            b_att |= 1 << (s - 7)
        PAWN_ATTACKS[1][s] = b_att & MASK64

        # 2. Knight Attacks
        n_att = 0
        for df, dr in KNIGHT_DELTAS:
            nf, nr = file + df, rank + dr
            if 0 <= nf < 8 and 0 <= nr < 8:
                n_att |= 1 << make_square(nf, nr)
        KNIGHT_ATTACKS[s] = n_att & MASK64

        # 3. King Attacks
        k_att = 0
        for df, dr in KING_DELTAS:
            nf, nr = file + df, rank + dr
            if 0 <= nf < 8 and 0 <= nr < 8:
                k_att |= 1 << make_square(nf, nr)
        KING_ATTACKS[s] = k_att & MASK64


_init_static_attacks()


def bishop_attacks(sq: Square, occupied: int) -> int:
    """Generate bishop attack rays given board occupancy."""
    attacks = 0
    file, rank = file_of(sq), rank_of(sq)
    deltas = [(-1, -1), (-1, 1), (1, -1), (1, 1)]
    for df, dr in deltas:
        nf, nr = file + df, rank + dr
        while 0 <= nf < 8 and 0 <= nr < 8:
            target = make_square(nf, nr)
            attacks |= 1 << target
            if occupied & (1 << target):
                break
            nf += df
            nr += dr
    return attacks & MASK64


def rook_attacks(sq: Square, occupied: int) -> int:
    """Generate rook attack rays given board occupancy."""
    attacks = 0
    file, rank = file_of(sq), rank_of(sq)
    deltas = [(-1, 0), (1, 0), (0, -1), (0, 1)]
    for df, dr in deltas:
        nf, nr = file + df, rank + dr
        while 0 <= nf < 8 and 0 <= nr < 8:
            target = make_square(nf, nr)
            attacks |= 1 << target
            if occupied & (1 << target):
                break
            nf += df
            nr += dr
    return attacks & MASK64


def queen_attacks(sq: Square, occupied: int) -> int:
    """Generate queen attack rays (rook + bishop)."""
    return (bishop_attacks(sq, occupied) | rook_attacks(sq, occupied)) & MASK64
