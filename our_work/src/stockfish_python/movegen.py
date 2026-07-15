"""Stockfish Legal Move Generator.

Translates candidate move generation, board transitions, en-passant, and castling
from Stockfish's C++ representation (movegen.h and movegen.cpp).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, List
from stockfish_python.types import Color, Piece, PieceType, Square, file_of, rank_of, make_square
from stockfish_python.bitboard import (
    pop_lsb, lsb, count_bits, KNIGHT_ATTACKS, KING_ATTACKS,
    bishop_attacks, rook_attacks, queen_attacks, PAWN_ATTACKS
)
from stockfish_python.position import Position


@dataclass(frozen=True)
class Move:
    """Represents a unique chess move transition."""

    from_sq: Square
    to_sq: Square
    promotion_type: PieceType = PieceType.NO_PIECE_TYPE

    def __str__(self) -> str:
        from stockfish_python.types import square_to_algebraic
        p_str = ""
        if self.promotion_type == PieceType.QUEEN: p_str = "q"
        elif self.promotion_type == PieceType.ROOK: p_str = "r"
        elif self.promotion_type == PieceType.BISHOP: p_str = "b"
        elif self.promotion_type == PieceType.KNIGHT: p_str = "n"
        return f"{square_to_algebraic(self.from_sq)}{square_to_algebraic(self.to_sq)}{p_str}"


def is_square_attacked(pos: Position, sq: Square, attacker_color: Color) -> bool:
    """Check if a square is attacked by any piece of the specified color."""
    occupied = pos.by_color[Color.WHITE] | pos.by_color[Color.BLACK]

    # Pawn attacks (check from perspective of target square)
    pawn_color = Color.BLACK if attacker_color == Color.WHITE else Color.WHITE
    pawns = pos.by_type[PieceType.PAWN] & pos.by_color[attacker_color]
    if PAWN_ATTACKS[pawn_color][sq] & pawns:
        return True

    # Knight attacks
    knights = pos.by_type[PieceType.KNIGHT] & pos.by_color[attacker_color]
    if KNIGHT_ATTACKS[sq] & knights:
        return True

    # King attacks
    king = pos.by_type[PieceType.KING] & pos.by_color[attacker_color]
    if KING_ATTACKS[sq] & king:
        return True

    # Bishop/Queen diagonal attacks
    bishops_queens = (pos.by_type[PieceType.BISHOP] | pos.by_type[PieceType.QUEEN]) & pos.by_color[attacker_color]
    if bishop_attacks(sq, occupied) & bishops_queens:
        return True

    # Rook/Queen straight line attacks
    rooks_queens = (pos.by_type[PieceType.ROOK] | pos.by_type[PieceType.QUEEN]) & pos.by_color[attacker_color]
    if rook_attacks(sq, occupied) & rooks_queens:
        return True

    return False


def in_check(pos: Position, color: Color) -> bool:
    """Return True if the specified player's King is in check."""
    king_bb = pos.by_type[PieceType.KING] & pos.by_color[color]
    if not king_bb:
        return False
    king_sq = lsb(king_bb)
    attacker_color = Color.BLACK if color == Color.WHITE else Color.WHITE
    return is_square_attacked(pos, king_sq, attacker_color)


def generate_pseudo_legal_moves(pos: Position) -> List[Move]:
    """Generate all candidate pseudo-legal moves for the active side."""
    moves: List[Move] = []
    co = pos.side_to_move
    opp_co = Color.BLACK if co == Color.WHITE else Color.WHITE
    occupied = pos.by_color[Color.WHITE] | pos.by_color[Color.BLACK]
    own_pieces = pos.by_color[co]

    # Loop over board positions
    for from_s in range(64):
        sq = Square(from_s)
        p = pos.board[sq]
        if p == Piece.NO_PIECE:
            continue

        p_co = Color.BLACK if p >= 9 else Color.WHITE
        if p_co != co:
            continue

        pt = PieceType(int(p) if co == Color.WHITE else int(p) - 8)

        # 1. Pawns
        if pt == PieceType.PAWN:
            direction = 1 if co == Color.WHITE else -1
            promo_rank = 7 if co == Color.WHITE else 0
            start_rank = 1 if co == Color.WHITE else 6

            # Single step forward
            one_step = Square(from_s + direction * 8)
            if pos.board[one_step] == Piece.NO_PIECE:
                if rank_of(one_step) == promo_rank:
                    for promo in [PieceType.QUEEN, PieceType.ROOK, PieceType.BISHOP, PieceType.KNIGHT]:
                        moves.append(Move(sq, one_step, promo))
                else:
                    moves.append(Move(sq, one_step))

                # Double step from starting rank
                if rank_of(sq) == start_rank:
                    two_step = Square(from_s + direction * 16)
                    if pos.board[two_step] == Piece.NO_PIECE:
                        moves.append(Move(sq, two_step))

            # Diagonal captures
            attacks = PAWN_ATTACKS[co][sq]
            # Standard captures or En Passant
            targets_bb = attacks & (pos.by_color[opp_co] | (1 << pos.ep_square if pos.ep_square != Square.SQ_NONE else 0))
            while targets_bb:
                to_sq, targets_bb = pop_lsb(targets_bb)
                if rank_of(to_sq) == promo_rank:
                    for promo in [PieceType.QUEEN, PieceType.ROOK, PieceType.BISHOP, PieceType.KNIGHT]:
                        moves.append(Move(sq, to_sq, promo))
                else:
                    moves.append(Move(sq, to_sq))

        # 2. Knight
        elif pt == PieceType.KNIGHT:
            targets_bb = KNIGHT_ATTACKS[sq] & ~own_pieces
            while targets_bb:
                to_sq, targets_bb = pop_lsb(targets_bb)
                moves.append(Move(sq, to_sq))

        # 3. King
        elif pt == PieceType.KING:
            targets_bb = KING_ATTACKS[sq] & ~own_pieces
            while targets_bb:
                to_sq, targets_bb = pop_lsb(targets_bb)
                moves.append(Move(sq, to_sq))

            # Castling (Check rights, occupancy, and attack status)
            if co == Color.WHITE:
                if (pos.castling_rights & 1) and not (occupied & ((1 << Square.F1) | (1 << Square.G1))):
                    if not in_check(pos, co) and not is_square_attacked(pos, Square.F1, opp_co):
                        moves.append(Move(Square.E1, Square.G1))
                if (pos.castling_rights & 2) and not (occupied & ((1 << Square.D1) | (1 << Square.C1) | (1 << Square.B1))):
                    if not in_check(pos, co) and not is_square_attacked(pos, Square.D1, opp_co):
                        moves.append(Move(Square.E1, Square.C1))
            else:
                if (pos.castling_rights & 4) and not (occupied & ((1 << Square.F8) | (1 << Square.G8))):
                    if not in_check(pos, co) and not is_square_attacked(pos, Square.F8, opp_co):
                        moves.append(Move(Square.E8, Square.G8))
                if (pos.castling_rights & 8) and not (occupied & ((1 << Square.D8) | (1 << Square.C8) | (1 << Square.B8))):
                    if not in_check(pos, co) and not is_square_attacked(pos, Square.D8, opp_co):
                        moves.append(Move(Square.E8, Square.C8))

        # 4. Sliders (Bishop, Rook, Queen)
        elif pt == PieceType.BISHOP:
            targets_bb = bishop_attacks(sq, occupied) & ~own_pieces
            while targets_bb:
                to_sq, targets_bb = pop_lsb(targets_bb)
                moves.append(Move(sq, to_sq))

        elif pt == PieceType.ROOK:
            targets_bb = rook_attacks(sq, occupied) & ~own_pieces
            while targets_bb:
                to_sq, targets_bb = pop_lsb(targets_bb)
                moves.append(Move(sq, to_sq))

        elif pt == PieceType.QUEEN:
            targets_bb = queen_attacks(sq, occupied) & ~own_pieces
            while targets_bb:
                to_sq, targets_bb = pop_lsb(targets_bb)
                moves.append(Move(sq, to_sq))

    return moves


def generate_legal_moves(pos: Position) -> List[Move]:
    """Generate all strict legal moves, filtering out moves that violate king safety."""
    legal: List[Move] = []
    co = pos.side_to_move
    pseudo = generate_pseudo_legal_moves(pos)
    for m in pseudo:
        captured = pos.board[m.to_sq]
        # Make the move
        pos.do_move(m.from_sq, m.to_sq, m.promotion_type)

        # Check if own King is attacked
        if not in_check(pos, co):
            legal.append(m)

        # Undo the move
        pos.undo_move(m.from_sq, m.to_sq, captured, m.promotion_type)
    return legal
