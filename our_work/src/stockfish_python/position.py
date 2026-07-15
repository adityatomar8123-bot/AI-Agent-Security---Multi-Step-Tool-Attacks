"""Stockfish Board Position Representation.

Translates the board occupancy maps, active player, castling rights, FEN parser,
and move execution logic from Stockfish's C++ representation (position.h and position.cpp).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final
from stockfish_python.types import Color, Piece, PieceType, Square, file_of, rank_of, make_square
from stockfish_python.bitboard import MASK64


@dataclass
class PositionState:
    """Historical state of a board position before a move, enabling undo operations."""

    castling_rights: int
    ep_square: Square
    halfmove_clock: int
    fullmove_number: int


class Position:
    """Represents a unique board position and its occupancy maps (bitboards)."""

    def __init__(self) -> None:
        self.board: list[Piece] = [Piece.NO_PIECE] * 64
        # Occupancy by color (WHITE=0, BLACK=1)
        self.by_color: list[int] = [0, 0]
        # Occupancy by piece type (index matches PieceType values)
        self.by_type: list[int] = [0] * 8
        self.side_to_move: Color = Color.WHITE
        self.castling_rights: int = 0  # 1: WK, 2: WQ, 4: BK, 8: BQ
        self.ep_square: Square = Square.SQ_NONE
        self.halfmove_clock: int = 0
        self.fullmove_number: int = 1
        self.history: list[PositionState] = []

    def clear(self) -> None:
        """Reset the position to empty."""
        self.board = [Piece.NO_PIECE] * 64
        self.by_color = [0, 0]
        self.by_type = [0] * 8
        self.side_to_move = Color.WHITE
        self.castling_rights = 0
        self.ep_square = Square.SQ_NONE
        self.halfmove_clock = 0
        self.fullmove_number = 1
        self.history = []

    def set_piece(self, sq: Square, p: Piece) -> None:
        """Place a piece on a square and update bitboard maps."""
        self.board[sq] = p
        if p == Piece.NO_PIECE:
            return

        # Determine color
        co = Color.BLACK if p >= 9 else Color.WHITE
        # Extract PieceType (offset pawns and sliders)
        pt = PieceType(int(p) if co == Color.WHITE else int(p) - 8)

        # Update bitboard maps
        self.by_color[co] |= 1 << sq
        self.by_type[pt] |= 1 << sq
        self.by_type[PieceType.ALL_PIECES] |= 1 << sq

    def remove_piece(self, sq: Square) -> None:
        """Remove a piece from a square."""
        p = self.board[sq]
        if p == Piece.NO_PIECE:
            return

        co = Color.BLACK if p >= 9 else Color.WHITE
        pt = PieceType(int(p) if co == Color.WHITE else int(p) - 8)

        # Clear maps
        self.by_color[co] &= ~(1 << sq)
        self.by_type[pt] &= ~(1 << sq)
        self.by_type[PieceType.ALL_PIECES] &= ~(1 << sq)
        self.board[sq] = Piece.NO_PIECE

    def set_fen(self, fen: str) -> None:
        """Parse and load a standard FEN string into the position."""
        self.clear()
        parts = fen.split()
        if not parts:
            return

        # 1. Piece placement
        rows = parts[0].split("/")
        for r_idx, row in enumerate(reversed(rows)):
            f_idx = 0
            for char in row:
                if char.isdigit():
                    f_idx += int(char)
                else:
                    piece_map = {
                        "P": Piece.W_PAWN, "N": Piece.W_KNIGHT, "B": Piece.W_BISHOP,
                        "R": Piece.W_ROOK, "Q": Piece.W_QUEEN, "K": Piece.W_KING,
                        "p": Piece.B_PAWN, "n": Piece.B_KNIGHT, "b": Piece.B_BISHOP,
                        "r": Piece.B_ROOK, "q": Piece.B_QUEEN, "k": Piece.B_KING
                    }
                    p = piece_map.get(char, Piece.NO_PIECE)
                    sq = make_square(f_idx, r_idx)
                    self.set_piece(sq, p)
                    f_idx += 1

        # 2. Side to move
        if len(parts) > 1:
            self.side_to_move = Color.BLACK if parts[1] == "b" else Color.WHITE

        # 3. Castling rights
        if len(parts) > 2:
            rights_str = parts[2]
            if "K" in rights_str: self.castling_rights |= 1
            if "Q" in rights_str: self.castling_rights |= 2
            if "k" in rights_str: self.castling_rights |= 4
            if "q" in rights_str: self.castling_rights |= 8

        # 4. En passant target
        if len(parts) > 3 and parts[3] != "-":
            from stockfish_python.types import algebraic_to_square
            self.ep_square = algebraic_to_square(parts[3])

        # 5. Halfmove and fullmove clocks
        if len(parts) > 4:
            self.halfmove_clock = int(parts[4])
        if len(parts) > 5:
            self.fullmove_number = int(parts[5])

    def do_move(self, from_sq: Square, to_sq: Square, promotion_type: PieceType = PieceType.NO_PIECE_TYPE) -> None:
        """Execute a move on the board, updating all positions, bitboards, and clocks."""
        p = self.board[from_sq]
        co = self.side_to_move

        # Cache historical state
        self.history.append(
            PositionState(
                castling_rights=self.castling_rights,
                ep_square=self.ep_square,
                halfmove_clock=self.halfmove_clock,
                fullmove_number=self.fullmove_number
            )
        )

        # Remove pieces from source and target
        captured = self.board[to_sq]
        self.remove_piece(from_sq)
        if captured != Piece.NO_PIECE:
            self.remove_piece(to_sq)
            self.halfmove_clock = 0
        else:
            self.halfmove_clock += 1

        # Handle En Passant capture
        if (p == Piece.W_PAWN or p == Piece.B_PAWN) and to_sq == self.ep_square:
            cap_sq = make_square(file_of(to_sq), rank_of(from_sq))
            self.remove_piece(cap_sq)

        # Handle Promotion
        if promotion_type != PieceType.NO_PIECE_TYPE:
            promo_p = Piece(int(promotion_type) + (8 if co == Color.BLACK else 0))
            self.set_piece(to_sq, promo_p)
            self.halfmove_clock = 0
        else:
            self.set_piece(to_sq, p)

        # Update En Passant square
        self.ep_square = Square.SQ_NONE
        if p == Piece.W_PAWN and rank_of(to_sq) - rank_of(from_sq) == 2:
            self.ep_square = make_square(file_of(from_sq), rank_of(from_sq) + 1)
        elif p == Piece.B_PAWN and rank_of(from_sq) - rank_of(to_sq) == 2:
            self.ep_square = make_square(file_of(from_sq), rank_of(from_sq) - 1)

        # Reset clock on Pawn push
        if p == Piece.W_PAWN or p == Piece.B_PAWN:
            self.halfmove_clock = 0

        # Adjust castling rights if rook/king moves
        if p == Piece.W_KING:
            self.castling_rights &= ~3
        elif p == Piece.B_KING:
            self.castling_rights &= ~12
        elif p == Piece.W_ROOK:
            if from_sq == Square.H1: self.castling_rights &= ~1
            elif from_sq == Square.A1: self.castling_rights &= ~2
        elif p == Piece.B_ROOK:
            if from_sq == Square.H8: self.castling_rights &= ~4
            elif from_sq == Square.A8: self.castling_rights &= ~8

        # Toggle active turn side
        self.side_to_move = Color.BLACK if co == Color.WHITE else Color.WHITE
        if co == Color.BLACK:
            self.fullmove_number += 1

    def undo_move(self, from_sq: Square, to_sq: Square, captured: Piece = Piece.NO_PIECE, promotion_type: PieceType = PieceType.NO_PIECE_TYPE) -> None:
        """Revert the last executed move using cached history state."""
        if not self.history:
            return

        state = self.history.pop()
        co = Color.WHITE if self.side_to_move == Color.BLACK else Color.BLACK

        # Piece on target square
        p = self.board[to_sq]

        # Revert promotion
        if promotion_type != PieceType.NO_PIECE_TYPE:
            p = Piece(Piece.W_PAWN if co == Color.WHITE else Piece.B_PAWN)

        self.remove_piece(to_sq)
        self.set_piece(from_sq, p)

        # Restore captured piece
        if captured != Piece.NO_PIECE:
            self.set_piece(to_sq, captured)

        # Restore En Passant capture target
        if (p == Piece.W_PAWN or p == Piece.B_PAWN) and to_sq == state.ep_square:
            cap_sq = make_square(file_of(to_sq), rank_of(from_sq))
            opp_p = Piece.B_PAWN if co == Color.WHITE else Piece.W_PAWN
            self.set_piece(cap_sq, opp_p)

        # Restore historical metadata
        self.castling_rights = state.castling_rights
        self.ep_square = state.ep_square
        self.halfmove_clock = state.halfmove_clock
        self.fullmove_number = state.fullmove_number
        self.side_to_move = co
