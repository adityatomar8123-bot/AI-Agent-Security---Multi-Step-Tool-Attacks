"""Stockfish Negamax Alpha-Beta Search Engine.

Translates iterative deepening, transposition table cuts, move ordering,
and alpha-beta minimax search from Stockfish's C++ codebase (search.cpp and search.h).
"""

from __future__ import annotations

import time
from typing import Final
from stockfish_python.types import Color
from stockfish_python.movegen import Move, generate_legal_moves
from stockfish_python.position import Position
from stockfish_python.evaluate import evaluate
from stockfish_python.tt import TranspositionTable, ZOBRIST, BOUND_EXACT, BOUND_ALPHA, BOUND_BETA

INFINITY: Final[float] = 1_000_000.0


class SearchEngine:
    """Core search engine implementing minimax with alpha-beta pruning."""

    def __init__(self, tt: TranspositionTable | None = None) -> None:
        self.tt: TranspositionTable = tt if tt is not None else TranspositionTable()
        self.nodes_visited: int = 0
        self.start_time: float = 0.0
        self.time_limit_s: float = 0.0
        self.stop_search: bool = False

    def order_moves(self, pos: Position, moves: list[Move], best_tt_move: Move | None) -> list[Move]:
        """Order moves to maximize Alpha-Beta pruning efficiency.

        Prioritizes the best move found in previous search depths, captures, and then quiet moves.
        """
        scored_moves = []
        for m in moves:
            score = 0.0
            # 1. Best move from Transposition Table
            if best_tt_move and m.from_sq == best_tt_move.from_sq and m.to_sq == best_tt_move.to_sq:
                score += 10000.0

            # 2. Captures (Simple MVV-LVA: Most Valuable Victim, Least Valuable Attacker)
            target_piece = pos.board[m.to_sq]
            if target_piece != 0:
                # Add victim value minus attacker value
                victim_val = abs(int(target_piece))
                attacker_val = abs(int(pos.board[m.from_sq]))
                score += 1000.0 + (victim_val - 0.1 * attacker_val)

            # 3. Promotion bonus
            if m.promotion_type != 0:
                score += 800.0

            scored_moves.append((score, m))

        # Sort moves in descending order of priority score
        scored_moves.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored_moves]

    def alphabeta(self, pos: Position, depth: int, alpha: float, beta: float) -> float:
        """Negamax Alpha-Beta search with Transposition Table cuts."""
        self.nodes_visited += 1

        # Check time limit periodically
        if self.nodes_visited % 1000 == 0:
            if self.time_limit_s > 0 and (time.time() - self.start_time) >= self.time_limit_s:
                self.stop_search = True

        if self.stop_search:
            return 0.0

        zkey = ZOBRIST.hash(pos)

        # 1. Probe Transposition Table
        tt_entry = self.tt.probe(zkey)
        if tt_entry and tt_entry.depth >= depth:
            if tt_entry.flag == BOUND_EXACT:
                return tt_entry.score
            elif tt_entry.flag == BOUND_ALPHA and tt_entry.score <= alpha:
                return alpha
            elif tt_entry.flag == BOUND_BETA and tt_entry.score >= beta:
                return beta

        # 2. Base case
        legal_moves = generate_legal_moves(pos)
        if depth == 0 or not legal_moves:
            # Negamax requires evaluation to be relative to the side to move
            # evaluate() returns positive if White is better.
            stand_pat = evaluate(pos)
            return stand_pat if pos.side_to_move == Color.WHITE else -stand_pat

        best_tt_move = tt_entry.best_move if tt_entry else None
        ordered_moves = self.order_moves(pos, legal_moves, best_tt_move)

        best_score = -INFINITY
        best_move = None
        flag = BOUND_ALPHA

        # 3. Explore child nodes
        for m in ordered_moves:
            captured = pos.board[m.to_sq]
            pos.do_move(m.from_sq, m.to_sq, m.promotion_type)

            # Negamax recursive call
            score = -self.alphabeta(pos, depth - 1, -beta, -alpha)

            pos.undo_move(m.from_sq, m.to_sq, captured, m.promotion_type)

            if self.stop_search:
                return 0.0

            if score > best_score:
                best_score = score
                best_move = m

            if score > alpha:
                alpha = score
                flag = BOUND_EXACT

            # Beta cutoff
            if score >= beta:
                self.tt.store(zkey, depth, score, BOUND_BETA, m)
                return score

        # Store search results in TT
        self.tt.store(zkey, depth, best_score, flag, best_move)
        return best_score

    def search(self, pos: Position, max_depth: int = 4, time_limit_s: float = 0.0) -> tuple[Move | None, float]:
        """Execute iterative deepening search to find the best move."""
        self.nodes_visited = 0
        self.start_time = time.time()
        self.time_limit_s = time_limit_s
        self.stop_search = False

        best_move = None
        best_score = -INFINITY

        # Iterative deepening loop
        for depth in range(1, max_depth + 1):
            if self.stop_search:
                break

            zkey = ZOBRIST.hash(pos)
            # Alpha-Beta root call
            score = self.alphabeta(pos, depth, -INFINITY, INFINITY)

            # Probe the TT to retrieve the best move at this depth
            entry = self.tt.probe(zkey)
            if entry and not self.stop_search:
                best_move = entry.best_move
                best_score = entry.score

        return best_move, best_score
