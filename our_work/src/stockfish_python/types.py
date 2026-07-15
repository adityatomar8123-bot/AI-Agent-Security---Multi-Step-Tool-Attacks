"""Stockfish Types and Board Constants.

Translates type definitions, color enums, piece enums, and square mappings
from Stockfish's C++ representation (types.h).
"""

from __future__ import annotations

from enum import IntEnum


class Color(IntEnum):
    """Active player side."""
    WHITE = 0
    BLACK = 1
    NO_COLOR = 2


class PieceType(IntEnum):
    """Piece categories (excluding color)."""
    NO_PIECE_TYPE = 0
    PAWN = 1
    KNIGHT = 2
    BISHOP = 3
    ROOK = 4
    QUEEN = 5
    KING = 6
    ALL_PIECES = 7


class Piece(IntEnum):
    """Colored pieces mapped to distinct integers."""
    NO_PIECE = 0
    W_PAWN = 1
    W_KNIGHT = 2
    W_BISHOP = 3
    W_ROOK = 4
    W_QUEEN = 5
    W_KING = 6
    B_PAWN = 9
    B_KNIGHT = 10
    B_BISHOP = 11
    B_ROOK = 12
    B_QUEEN = 13
    B_KING = 14


# Square mappings A1 to H8 mapped 0 to 63
class Square(IntEnum):
    A1 = 0; B1 = 1; C1 = 2; D1 = 3; E1 = 4; F1 = 5; G1 = 6; H1 = 7
    A2 = 8; B2 = 9; C2 = 10; D2 = 11; E2 = 12; F2 = 13; G2 = 14; H2 = 15
    A3 = 16; B3 = 17; C3 = 18; D3 = 19; E3 = 20; F3 = 21; G3 = 22; H3 = 23
    A4 = 24; B4 = 25; C4 = 26; D4 = 27; E4 = 28; F4 = 29; G4 = 30; H4 = 31
    A5 = 32; B5 = 33; C5 = 34; D5 = 35; E5 = 36; F5 = 37; G5 = 38; H5 = 39
    A6 = 40; B6 = 41; C6 = 42; D6 = 43; E6 = 44; F6 = 45; G6 = 46; H6 = 47
    A7 = 48; B7 = 49; C7 = 50; D7 = 51; E7 = 52; F7 = 53; G7 = 54; H7 = 55
    A8 = 56; B8 = 57; C8 = 58; D8 = 59; E8 = 60; F8 = 61; G8 = 62; H8 = 63
    SQ_NONE = 64


# Helper arrays
SQUARES: list[Square] = [Square(i) for i in range(64)]

FILE_NAMES = ["a", "b", "c", "d", "e", "f", "g", "h"]
RANK_NAMES = ["1", "2", "3", "4", "5", "6", "7", "8"]


def make_square(file: int, rank: int) -> Square:
    """Return a Square from 0-based file and rank coordinates."""
    return Square((rank << 3) + file)


def file_of(sq: Square) -> int:
    """Get the file (0-7) of a square."""
    return int(sq) & 7


def rank_of(sq: Square) -> int:
    """Get the rank (0-7) of a square."""
    return int(sq) >> 3


def square_to_algebraic(sq: Square) -> str:
    """Convert square to UCI algebraic notation (e.g. e4)."""
    if sq == Square.SQ_NONE:
        return "-"
    return FILE_NAMES[file_of(sq)] + RANK_NAMES[rank_of(sq)]


def algebraic_to_square(name: str) -> Square:
    """Convert algebraic notation (e.g. e4) to a Square enum."""
    if len(name) != 2:
        return Square.SQ_NONE
    file = FILE_NAMES.index(name[0])
    rank = RANK_NAMES.index(name[1])
    return make_square(file, rank)
