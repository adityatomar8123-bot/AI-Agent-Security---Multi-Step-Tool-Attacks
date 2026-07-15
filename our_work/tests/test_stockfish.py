"""Unit Tests for Python-Translated Stockfish Engine.

Validates that board setups, legal move generation, transposition caching,
and Alpha-Beta search operate correctly.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Add src/ to sys.path to resolve stockfish_python imports
project_root = Path(__file__).resolve().parent.parent
src_path = project_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from stockfish_python.types import Color, Piece, PieceType, Square, make_square, file_of, rank_of
from stockfish_python.position import Position
from stockfish_python.movegen import generate_legal_moves, in_check
from stockfish_python.evaluate import evaluate
from stockfish_python.tt import TranspositionTable, ZOBRIST, BOUND_EXACT
from stockfish_python.search import SearchEngine


class TestStockfishPython(unittest.TestCase):
    """Verifies correctness of Stockfish Python translation modules."""

    def test_types_and_coordinates(self) -> None:
        """Validate square coordinate construction and file/rank extractors."""
        self.assertEqual(make_square(4, 3), Square.E4)
        self.assertEqual(file_of(Square.E4), 4)  # file 'e' is index 4
        self.assertEqual(rank_of(Square.E4), 3)  # rank 4 is index 3

    def test_position_fen_parser(self) -> None:
        """Validate FEN string parsing and board setup occupancy."""
        pos = Position()
        # Load standard start position FEN
        pos.set_fen("rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1")

        self.assertEqual(pos.side_to_move, Color.WHITE)
        self.assertEqual(pos.board[Square.E1], Piece.W_KING)
        self.assertEqual(pos.board[Square.E8], Piece.B_KING)
        self.assertEqual(pos.board[Square.E4], Piece.NO_PIECE)

        # Check occupancy bitboards
        all_occupied = pos.by_color[Color.WHITE] | pos.by_color[Color.BLACK]
        # Starting rank 1 and 2 occupied, 7 and 8 occupied -> 32 pieces set
        self.assertEqual(bin(all_occupied).count("1"), 32)

    def test_move_generation(self) -> None:
        """Verify legal moves generated on starting board (20 legal moves)."""
        pos = Position()
        pos.set_fen("rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1")

        legal_moves = generate_legal_moves(pos)
        # Standard starting position has exactly 20 legal moves (16 pawn pushes + 4 knight moves)
        self.assertEqual(len(legal_moves), 20)

    def test_make_undo_move(self) -> None:
        """Verify making and unmaking moves updates the board state correctly."""
        pos = Position()
        pos.set_fen("rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1")

        # White plays e2e4
        pos.do_move(Square.E2, Square.E4)
        self.assertEqual(pos.board[Square.E2], Piece.NO_PIECE)
        self.assertEqual(pos.board[Square.E4], Piece.W_PAWN)
        self.assertEqual(pos.side_to_move, Color.BLACK)

        # Revert move
        pos.undo_move(Square.E2, Square.E4)
        self.assertEqual(pos.board[Square.E2], Piece.W_PAWN)
        self.assertEqual(pos.board[Square.E4], Piece.NO_PIECE)
        self.assertEqual(pos.side_to_move, Color.WHITE)

    def test_transposition_table(self) -> None:
        """Verify Zobrist hashing and Transposition Table cache hits."""
        pos = Position()
        pos.set_fen("rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1")

        key1 = ZOBRIST.hash(pos)
        pos.do_move(Square.E2, Square.E4)
        key2 = ZOBRIST.hash(pos)
        self.assertNotEqual(key1, key2)

        # Revert
        pos.undo_move(Square.E2, Square.E4)
        key1_reverted = ZOBRIST.hash(pos)
        self.assertEqual(key1, key1_reverted)

        # Probe TT
        tt = TranspositionTable()
        tt.store(key1, depth=3, score=15.0, flag=BOUND_EXACT, best_move=None)
        entry = tt.probe(key1)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.score, 15.0)

    def test_evaluator_symmetry(self) -> None:
        """Verify board evaluation is symmetrical on start positions."""
        pos = Position()
        pos.set_fen("rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1")

        score = evaluate(pos)
        # In start position, white and black are exactly symmetric, score should be near 0
        self.assertEqual(score, 0.0)

    def test_alpha_beta_search(self) -> None:
        """Verify search completes and finds a valid move."""
        pos = Position()
        pos.set_fen("r1bqkbnr/pppppppp/n7/8/4P3/8/PPPP1PPP/RNBQKBNR w KQkq - 0 1")

        searcher = SearchEngine()
        best_move, best_score = searcher.search(pos, max_depth=2)

        self.assertIsNotNone(best_move)
        # Search should return a Move object
        self.assertTrue(best_move.from_sq != Square.SQ_NONE)


if __name__ == "__main__":
    unittest.main()
