import torch
import torch.nn as nn

# ----------------- Deep Learning Models -----------------

class MLP(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_classes=2):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, num_classes)
        self.relu = nn.ReLU()

    def forward(self, x):
        x = self.relu(self.fc1(x))
        return self.fc2(x)


class CNN1D(nn.Module):
    def __init__(self, num_features, seq_len=None, num_classes=2):
        super().__init__()
        self.conv1 = nn.Conv1d(1, 64, kernel_size=3, padding=1)
        self.pool = nn.MaxPool1d(2)
        self.conv2 = nn.Conv1d(64, 128, kernel_size=3, padding=1)
        self.relu = nn.ReLU()
        self.fc_dynamic = None
        self.fc2 = nn.Linear(64, num_classes)

    def forward(self, x):
        # x: [batch, features] → convert to [batch, 1, features]
        if x.dim() == 2:
            x = x.unsqueeze(1)
        x = self.relu(self.conv1(x))
        x = self.pool(self.relu(self.conv2(x)))
        x = torch.flatten(x, 1)
        if self.fc_dynamic is None:
            self.fc_dynamic = nn.Linear(x.size(1), 64).to(x.device)
        x = self.relu(self.fc_dynamic(x))
        return self.fc2(x)


class LSTMModel(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_classes=2):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, num_classes)

    def forward(self, x):
        # ensure 3D: [batch, seq_len, features]
        if x.dim() == 2:
            x = x.unsqueeze(1)
        _, (h, _) = self.lstm(x)
        return self.fc(h[-1])


class GRUModel(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_classes=2):
        super().__init__()
        self.gru = nn.GRU(input_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, num_classes)

    def forward(self, x):
        if x.dim() == 2:
            x = x.unsqueeze(1)
        _, h = self.gru(x)
        return self.fc(h[-1])


class BiLSTM(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_classes=2):
        super().__init__()
        self.bilstm = nn.LSTM(input_dim, hidden_dim, batch_first=True, bidirectional=True)
        self.fc = nn.Linear(hidden_dim * 2, num_classes)

    def forward(self, x):
        if x.dim() == 2:
            x = x.unsqueeze(1)
        _, (h, _) = self.bilstm(x)
        h = torch.cat((h[-2], h[-1]), dim=1)
        return self.fc(h)


class CNN_LSTM(nn.Module):
    def __init__(self, input_dim, seq_len=None, hidden_dim=64, num_classes=2):
        super().__init__()
        self.conv1 = nn.Conv1d(1, 64, kernel_size=3, padding=1)
        self.pool = nn.MaxPool1d(2)
        self.lstm = nn.LSTM(64, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, num_classes)
        self.relu = nn.ReLU()

    def forward(self, x):
        if x.dim() == 2:
            x = x.unsqueeze(1)
        x = self.pool(self.relu(self.conv1(x)))
        x = x.permute(0, 2, 1)  # [batch, seq_len, features] for LSTM
        _, (h, _) = self.lstm(x)
        return self.fc(h[-1])


class CNN_GRU(nn.Module):
    def __init__(self, input_dim, seq_len=None, hidden_dim=64, num_classes=2):
        super().__init__()
        self.conv1 = nn.Conv1d(1, 64, kernel_size=3, padding=1)
        self.pool = nn.MaxPool1d(2)
        self.gru = nn.GRU(64, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, num_classes)
        self.relu = nn.ReLU()

    def forward(self, x):
        if x.dim() == 2:
            x = x.unsqueeze(1)
        x = self.pool(self.relu(self.conv1(x)))
        x = x.permute(0, 2, 1)
        _, h = self.gru(x)
        return self.fc(h[-1])


class AttentionLSTM(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_classes=2):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.attn = nn.Linear(hidden_dim, 1)
        self.fc = nn.Linear(hidden_dim, num_classes)

    def forward(self, x):
        if x.dim() == 2:
            x = x.unsqueeze(1)
        out, _ = self.lstm(x)
        attn_weights = torch.softmax(self.attn(out), dim=1)
        context = torch.sum(attn_weights * out, dim=1)
        return self.fc(context)


class AttentionGRU(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_classes=2):
        super().__init__()
        self.gru = nn.GRU(input_dim, hidden_dim, batch_first=True)
        self.attn = nn.Linear(hidden_dim, 1)
        self.fc = nn.Linear(hidden_dim, num_classes)

    def forward(self, x):
        if x.dim() == 2:
            x = x.unsqueeze(1)
        out, _ = self.gru(x)
        attn_weights = torch.softmax(self.attn(out), dim=1)
        context = torch.sum(attn_weights * out, dim=1)
        return self.fc(context)


class TransformerModel(nn.Module):
    def __init__(self, input_dim, num_heads=4, hidden_dim=64, num_classes=2, num_layers=1):
        super().__init__()
        encoder_layer = nn.TransformerEncoderLayer(d_model=input_dim, nhead=num_heads, dim_feedforward=hidden_dim)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.fc = nn.Linear(input_dim, num_classes)

    def forward(self, x):
        if x.dim() == 2:
            x = x.unsqueeze(1)
        # transformer expects [seq_len, batch, features]
        x = x.permute(1, 0, 2)
        out = self.transformer(x)
        out = out.mean(dim=0)
        return self.fc(out)
