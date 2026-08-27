"""Causal next-frame predictor models for the IDS.

All four classes share the same forward / inference contract:

  forward(x)         x.shape = (B, W, F)        → (B, W-1, F)
                     teacher-forced predictions of frames x_{1..W-1}
                     from x_{0..W-2}.  Trained with MSE vs x[:, 1:, :].

  predict_next(h)    h.shape = (B, T, F)        → (B, F)
                     given a history of T frames, return the prediction
                     for the (T+1)-th frame. Used at inference: history
                     is the first 31 entries of the length-32 ring buffer,
                     score = MSE between predict_next(history) and the
                     newly-arrived frame.

Variants:
  LSTMPredictor          1-layer LSTM + Linear         (current default)
  GRUPredictor           1-layer GRU + Linear
  TransformerPredictor   causal self-attention + Linear
  TCNPredictor           dilated causal convolutions + Linear
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

import torch
from torch import nn
import torch.nn.functional as F


# ---------- shared base ----------

class BasePredictor(nn.Module):
    """Shared save / load / config plumbing."""
    KIND: str = "base"

    def forward(self, x: torch.Tensor) -> torch.Tensor:        # pragma: no cover
        raise NotImplementedError

    def predict_next(self, history: torch.Tensor) -> torch.Tensor:   # pragma: no cover
        raise NotImplementedError

    def config(self) -> dict:                                  # pragma: no cover
        raise NotImplementedError

    def save(self, path: Path) -> None:
        torch.save({"state_dict": self.state_dict(),
                    "config": self.config()}, path)

    @classmethod
    def load(cls, path: Path, map_location="cpu") -> "BasePredictor":
        blob = torch.load(path, map_location=map_location, weights_only=True)
        cfg = dict(blob["config"])
        cfg.pop("kind", None)
        m = cls(**cfg)
        m.load_state_dict(blob["state_dict"])
        m.eval()
        return m


# ---------- LSTM ----------

class LSTMPredictor(BasePredictor):
    KIND = "lstm"

    def __init__(self, input_dim: int, hidden_dims: Sequence[int] = (8,),
                 window: int = 32):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dims = [int(h) for h in hidden_dims]
        self.window = window
        layers = []
        prev = input_dim
        for h in self.hidden_dims:
            layers.append(nn.LSTM(prev, h, num_layers=1, batch_first=True))
            prev = h
        self.layers = nn.ModuleList(layers)
        self.out = nn.Linear(self.hidden_dims[-1], input_dim)

    def _run(self, x: torch.Tensor) -> torch.Tensor:
        h = x
        for lstm in self.layers:
            h, _ = lstm(h)
        return h

    def forward(self, x):
        h = self._run(x[:, :-1, :])
        return self.out(h)

    def predict_next(self, history):
        h = self._run(history)
        return self.out(h[:, -1, :])

    def config(self):
        return {"input_dim": self.input_dim, "hidden_dims": self.hidden_dims,
                "window": self.window, "kind": self.KIND}


# back-compat alias for older checkpoints / imports
NextFramePredictor = LSTMPredictor


# ---------- GRU ----------

class GRUPredictor(BasePredictor):
    KIND = "gru"

    def __init__(self, input_dim: int, hidden_dims: Sequence[int] = (8,),
                 window: int = 32):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dims = [int(h) for h in hidden_dims]
        self.window = window
        layers = []
        prev = input_dim
        for h in self.hidden_dims:
            layers.append(nn.GRU(prev, h, num_layers=1, batch_first=True))
            prev = h
        self.layers = nn.ModuleList(layers)
        self.out = nn.Linear(self.hidden_dims[-1], input_dim)

    def _run(self, x):
        h = x
        for gru in self.layers:
            h, _ = gru(h)
        return h

    def forward(self, x):
        h = self._run(x[:, :-1, :])
        return self.out(h)

    def predict_next(self, history):
        h = self._run(history)
        return self.out(h[:, -1, :])

    def config(self):
        return {"input_dim": self.input_dim, "hidden_dims": self.hidden_dims,
                "window": self.window, "kind": self.KIND}


# ---------- Transformer (causal) ----------

class TransformerPredictor(BasePredictor):
    KIND = "transformer"

    def __init__(self, input_dim: int, d_model: int = 8, nhead: int = 1,
                 dim_feedforward: int = 16, num_layers: int = 1,
                 window: int = 32):
        super().__init__()
        self.input_dim = input_dim
        self.d_model = d_model
        self.nhead = nhead
        self.dim_feedforward = dim_feedforward
        self.num_layers = num_layers
        self.window = window
        self.in_proj = nn.Linear(input_dim, d_model)
        self.pos_emb = nn.Embedding(window, d_model)
        enc_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=dim_feedforward,
            batch_first=True, dropout=0.0)
        self.encoder = nn.TransformerEncoder(enc_layer, num_layers=num_layers)
        self.out = nn.Linear(d_model, input_dim)

    @staticmethod
    def _causal_mask(T: int, device) -> torch.Tensor:
        return torch.triu(torch.ones(T, T, device=device), diagonal=1).bool()

    def _embed(self, x: torch.Tensor) -> torch.Tensor:
        B, T, _ = x.shape
        h = self.in_proj(x)
        pos = torch.arange(T, device=x.device).unsqueeze(0).expand(B, -1)
        return h + self.pos_emb(pos)

    def forward(self, x):
        history = x[:, :-1, :]
        h = self._embed(history)
        mask = self._causal_mask(history.shape[1], x.device)
        h = self.encoder(h, mask=mask, is_causal=True)
        return self.out(h)

    def predict_next(self, history):
        h = self._embed(history)
        mask = self._causal_mask(history.shape[1], history.device)
        h = self.encoder(h, mask=mask, is_causal=True)
        return self.out(h[:, -1, :])

    def config(self):
        return {"input_dim": self.input_dim, "d_model": self.d_model,
                "nhead": self.nhead, "dim_feedforward": self.dim_feedforward,
                "num_layers": self.num_layers, "window": self.window,
                "kind": self.KIND}


# ---------- TCN (Temporal Convolutional Network) ----------

class TCNPredictor(BasePredictor):
    """Stack of dilated causal 1D convolutions. Receptive field with
    kernel_size=3 and dilations=(1,2,4,8) is 31 frames — fills the W-1=31
    history exactly when window=32.
    """
    KIND = "tcn"

    def __init__(self, input_dim: int, hidden: int = 8, kernel_size: int = 3,
                 dilations: Sequence[int] = (1, 2, 4, 8), window: int = 32):
        super().__init__()
        self.input_dim = input_dim
        self.hidden = hidden
        self.kernel_size = kernel_size
        self.dilations = list(dilations)
        self.window = window
        in_ch = input_dim
        convs = []
        for d in self.dilations:
            convs.append(nn.Conv1d(in_ch, hidden, kernel_size, dilation=d,
                                    padding=0))
            in_ch = hidden
        self.convs = nn.ModuleList(convs)
        self.out = nn.Linear(hidden, input_dim)

    def _run(self, x_BTF: torch.Tensor) -> torch.Tensor:
        # x_BTF: (B, T, F) → returns (B, T, hidden)
        h = x_BTF.transpose(1, 2)  # (B, F, T)
        for d, conv in zip(self.dilations, self.convs):
            pad = (self.kernel_size - 1) * d
            h = F.pad(h, (pad, 0))   # strictly left (causal) padding
            h = F.relu(conv(h))
        return h.transpose(1, 2)     # (B, T, hidden)

    def forward(self, x):
        history = x[:, :-1, :]                  # (B, T-1, F)
        h = self._run(history)                  # (B, T-1, hidden)
        return self.out(h)                      # (B, T-1, F)

    def predict_next(self, history):
        h = self._run(history)                  # (B, T, hidden)
        return self.out(h[:, -1, :])            # (B, F)

    def config(self):
        return {"input_dim": self.input_dim, "hidden": self.hidden,
                "kernel_size": self.kernel_size, "dilations": self.dilations,
                "window": self.window, "kind": self.KIND}


# ---------- registry + dispatcher ----------

MODEL_REGISTRY: dict[str, type[BasePredictor]] = {
    LSTMPredictor.KIND: LSTMPredictor,
    GRUPredictor.KIND: GRUPredictor,
    TransformerPredictor.KIND: TransformerPredictor,
    TCNPredictor.KIND: TCNPredictor,
    "predictor": LSTMPredictor,  # back-compat with old checkpoints
}


def load_predictor(path: Path, map_location="cpu") -> BasePredictor:
    """Load any predictor type by inspecting the kind field in its config."""
    blob = torch.load(path, map_location=map_location, weights_only=True)
    cfg = dict(blob["config"])
    kind = cfg.pop("kind", LSTMPredictor.KIND)
    cls = MODEL_REGISTRY[kind]
    m = cls(**cfg)
    m.load_state_dict(blob["state_dict"])
    m.eval()
    return m


# ---------- thresholds ----------

def save_threshold(value: float, path: Path) -> None:
    path.write_text(json.dumps({"threshold": float(value)}, indent=2))


def load_threshold(path: Path) -> float:
    return float(json.loads(path.read_text())["threshold"])
