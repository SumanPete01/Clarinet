import os
import pickle
import torch
import torch.nn as nn
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from torch.utils.data import DataLoader, TensorDataset

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH  = os.path.join(BASE_DIR, "data", "df_top6_undersampled.csv")
MODEL_PATH = os.path.join(BASE_DIR, "data", "transformer_model.pth")
SCALER_PATH = os.path.join(BASE_DIR, "data", "scaler.pkl")

# ── Label mapping ──────────────────────────────────────────────────────────────
LABEL_NAMES = ["BENIGN", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS slowloris", "FTP-Patator"]

# ── Model Architecture ─────────────────────────────────────────────────────────
class FeatureTokenizer(nn.Module):
    def __init__(self, num_features, d_model):
        super().__init__()
        self.value_projection = nn.Linear(1, d_model)
        self.feature_embedding = nn.Parameter(torch.randn(num_features, d_model))

    def forward(self, x):
        x = x.unsqueeze(-1)
        x = self.value_projection(x)
        x = x + self.feature_embedding
        return x


class TabularTransformer(nn.Module):
    def __init__(self, num_features=58, num_classes=6, d_model=64, n_heads=4, depth=2, dropout=0.1):
        super().__init__()
        self.tokenizer = FeatureTokenizer(num_features, d_model)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=n_heads,
            dim_feedforward=d_model * 4,
            dropout=dropout, batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=depth)
        self.cls_token = nn.Parameter(torch.randn(1, 1, d_model))
        self.classifier = nn.Sequential(
            nn.LayerNorm(d_model),
            nn.Linear(d_model, 256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, num_classes)
        )

    def forward(self, x):
        batch_size = x.size(0)
        x = self.tokenizer(x)
        cls_tokens = self.cls_token.expand(batch_size, -1, -1)
        x = torch.cat((cls_tokens, x), dim=1)
        x = self.transformer(x)
        cls_output = x[:, 0]
        return self.classifier(cls_output)


# ── Data Loading ───────────────────────────────────────────────────────────────
print("Loading data...")
df = pd.read_csv(DATA_PATH)
print(f"  Shape: {df.shape}")
print(f"  Class distribution:\n{df['Label'].value_counts().sort_index().to_string()}")

X = df.drop("Label", axis=1).values
y = df["Label"].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

X_train_t = torch.tensor(X_train, dtype=torch.float32)
y_train_t  = torch.tensor(y_train, dtype=torch.long)
X_test_t   = torch.tensor(X_test,  dtype=torch.float32)
y_test_t   = torch.tensor(y_test,  dtype=torch.long)

train_loader = DataLoader(TensorDataset(X_train_t, y_train_t), batch_size=256, shuffle=True)
test_loader  = DataLoader(TensorDataset(X_test_t,  y_test_t),  batch_size=256)

# ── Training ───────────────────────────────────────────────────────────────────
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"\nUsing device: {device}")

num_features = X_train.shape[1]
model = TabularTransformer(num_features=num_features, num_classes=6).to(device)

criterion = nn.CrossEntropyLoss()
optimizer = torch.optim.AdamW(model.parameters(), lr=1e-4)

EPOCHS = 20
print(f"\nTraining for {EPOCHS} epochs on {len(X_train)} samples...\n")

for epoch in range(EPOCHS):
    model.train()
    total_loss, correct, total = 0, 0, 0

    for xb, yb in train_loader:
        xb, yb = xb.to(device), yb.to(device)
        optimizer.zero_grad()
        out  = model(xb)
        loss = criterion(out, yb)
        loss.backward()
        optimizer.step()

        total_loss += loss.item()
        correct    += (out.argmax(1) == yb).sum().item()
        total      += yb.size(0)

    print(f"Epoch {epoch+1:2d}/{EPOCHS} | Loss: {total_loss/len(train_loader):.4f} | Train Acc: {correct/total:.4f}")

# ── Evaluation ─────────────────────────────────────────────────────────────────
print("\nEvaluating on test set...")
model.eval()
all_preds, all_labels = [], []

with torch.no_grad():
    for xb, yb in test_loader:
        xb = xb.to(device)
        preds = model(xb).argmax(1)
        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(yb.numpy())

print(classification_report(all_labels, all_preds, target_names=LABEL_NAMES))

# ── Save Model & Scaler ────────────────────────────────────────────────────────
print("Saving model and scaler...")
torch.save(model.state_dict(), MODEL_PATH)
with open(SCALER_PATH, "wb") as f:
    pickle.dump(scaler, f)

print(f"  ✅ Model  saved → {MODEL_PATH}")
print(f"  ✅ Scaler saved → {SCALER_PATH}")
