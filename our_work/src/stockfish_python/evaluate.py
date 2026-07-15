"""Stockfish Position Evaluator.

Translates material valuation and Piece-Square Tables (PST)
from Stockfish's C++ representation (evaluate.cpp and evaluate.h).
"""

from __future__ import annotations

from typing import Final
from stockfish_python.types import Color, Piece, PieceType, Square, file_of, rank_of
from stockfish_python.position import Position

# Piece values matching standard values
PIECE_VALUES: Final[dict[PieceType, float]] = {
    PieceType.PAWN: 100.0,
    PieceType.KNIGHT: 320.0,
    PieceType.BISHOP: 330.0,
    PieceType.ROOK: 500.0,
    PieceType.QUEEN: 900.0,
    PieceType.KING: 20000.0
}

# Piece-Square Tables (From white's perspective; mirrored for black)
PST_PAWN: Final[list[float]] = [
    0,  0,  0,  0,  0,  0,  0,  0,
    50, 50, 50, 50, 50, 50, 50, 50,
    10, 10, 20, 30, 30, 20, 10, 10,
     5,  5, 10, 25, 25, 10,  5,  5,
     0,  0,  0, 20, 20,  0,  0,  0,
     5, -5,-10,  0,  0,-10, -5,  5,
     5, 10, 10,-20,-20, 10, 10,  5,
     0,  0,  0,  0,  0,  0,  0,  0
]

PST_KNIGHT: Final[list[float]] = [
    -50,-40,-30,-30,-30,-30,-40,-50,
    -40,-20,  0,  0,  0,  0,-20,-40,
    -30,  0, 10, 15, 15, 10,  0,-30,
    -30,  5, 15, 20, 20, 15,  5,-30,
    -30,  0, 15, 20, 20, 15,  0,-30,
    -30,  5, 10, 15, 15, 10,  5,-30,
    -40,-20,  0,  5,  5,  0,-20,-40,
    -50,-40,-30,-30,-30,-30,-40,-50
]

PST_BISHOP: Final[list[float]] = [
    -20,-10,-10,-10,-10,-10,-10,-20,
    -10,  0,  0,  0,  0,  0,  0,-10,
    -10,  0,  5, 10, 10,  5,  0,-10,
    -10,  5,  5, 10, 10,  5,  5,-10,
    -10,  0, 10, 10, 10, 10,  0,-10,
    -10, 10, 10, 10, 10, 10, 10,-10,
    -10,  5,  0,  0,  0,  0,  5,-10,
    -20,-10,-10,-10,-10,-10,-10,-20
]

PST_ROOK: Final[list[float]] = [
      0,  0,  0,  0,  0,  0,  0,  0,
      5, 10, 10, 10, 10, 10, 10,  5,
     -5,  0,  0,  0,  0,  0,  0, -5,
     -5,  0,  0,  0,  0,  0,  0, -5,
     -5,  0,  0,  0,  0,  0,  0, -5,
     -5,  0,  0,  0,  0,  0,  0, -5,
     -5,  0,  0,  0,  0,  0,  0, -5,
      0,  0,  0,  5,  5,  0,  0,  0
]

PST_QUEEN: Final[list[float]] = [
    -20,-10,-10, -5, -5,-10,-10,-20,
    -10,  0,  0,  0,  0,  0,  0,-10,
    -10,  0,  5,  5,  5,  5,  0,-10,
     -5,  0,  5,  5,  5,  5,  0, -5,
      0,  0,  5,  5,  5,  5,  0, -5,
    -10,  5,  5,  5,  5,  5,  5,-10,
    -10,  0,  5,  0,  0,  5,  0,-10,
    -20,-10,-10, -5, -5,-10,-10,-20
]

# King tables for middle game safety (safety in corners)
PST_KING_MID: Final[list[float]] = [
    -30,-40,-40,-50,-50,-40,-40,-30,
    -30,-40,-40,-50,-50,-40,-40,-30,
    -30,-40,-40,-50,-50,-40,-40,-30,
    -30,-40,-40,-50,-50,-40,-40,-30,
    -20,-30,-30,-40,-40,-30,-30,-20,
    -10,-20,-20,-20,-20,-20,-20,-10,
     20, 20,  0,  0,  0,  0, 20, 20,
     20, 30, 10,  0,  0, 10, 30, 20
]

PST_TABLES: Final[dict[PieceType, list[float]]] = {
    PieceType.PAWN: PST_PAWN,
    PieceType.KNIGHT: PST_KNIGHT,
    PieceType.BISHOP: PST_BISHOP,
    PieceType.ROOK: PST_ROOK,
    PieceType.QUEEN: PST_QUEEN,
    PieceType.KING: PST_KING_MID
}


def evaluate(pos: Position) -> float:
    """Evaluate the current board position.

    Returns positive scores if White is better, negative if Black is better.
    Calculates material values + Piece-Square Table offsets.
    """
    score = 0.0

    for s in range(64):
        sq = Square(s)
        p = pos.board[sq]
        if p == Piece.NO_PIECE:
            continue

        # Extract piece color
        co = Color.BLACK if p >= 9 else Color.WHITE
        # Extract PieceType
        pt = PieceType(int(p) if co == Color.WHITE else int(p) - 8)

        # Get base value
        value = PIECE_VALUES.get(pt, 0.0)

        # Get Piece-Square Table lookup
        # Black square indices are mirrored vertically (ranks inverted)
        pst_index = (56 - (rank_of(sq) << 3) + file_of(sq)) if co == Color.BLACK else s
        pst_bonus = PST_TABLES.get(pt, [0.0] * 64)[pst_index]

        total_value = value + pst_bonus

        if co == Color.WHITE:
            score += total_value
        else:
            score -= total_value

    return score
