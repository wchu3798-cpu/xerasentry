# XeraSentry

Real-time Ethereum security monitoring system built in Python.

## What it does

Monitors Ethereum blockchain in real-time and alerts you to:
- 🐋 Whale movements (50+ ETH transfers)
- 💰 High-value transfers (configurable threshold)
- ⛔ Sanctioned addresses (OFAC compliance)
- 👁️ Activity on wallets you're watching
- 🔴 Address poisoning attacks
- 🤖 MEV bot activity

## Features

- 10 modular detection rules
- Google Sheets integration for alerts
- SQLite database with indexed queries
- RPC failover system (5 backup endpoints)
- Transaction deduplication
- Memory-managed tracking
- Runs 100% locally (no API keys needed)

## Quick Start

### Install Requirements
```bash
pip install web3 python-dotenv requests
```

### Run Your First Scan
```python
python xerasentry.py

# Then in Python:
quick_scan()  # Scan 1 block
deep_scan()   # Scan 3 blocks
```

### Examples
```python
# Watch Vitalik's wallet
watch_address('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045')

# Watch Binance hot wallet
watch_address('0x28C6c06298d514Db089934071355E5743bf21d60')

# Lower threshold to catch more alerts
config.HIGH_VALUE_THRESHOLD = 0.3
deep_scan()

# Check system health
health_check()
```

## Google Sheets Integration (Optional)

Get alerts automatically saved to Google Sheets:

1. Create a Google Sheet with headers: `Timestamp | Severity | Rule Name | Message | TX Hash | From | To | Value | Block`
2. Go to Extensions → Apps Script
3. Paste the webhook code (see documentation)
4. Deploy as Web App
5. Set `config.GOOGLE_SHEETS_URL = 'your_webhook_url'`

## Tech Stack

- Python 3.8+
- Web3.py for blockchain interaction
- SQLite for alert persistence
- Google Sheets API for notifications

## License

MIT License - Open source and free to use

## Contributing

Feedback and contributions welcome! Open an issue or submit a PR.

## Roadmap

- [ ] Telegram/Discord webhook support
- [ ] Multi-chain support (Polygon, BSC)
- [ ] Web dashboard
- [ ] Email notifications
- [ ] Custom detection rules

---

Built by a solo developer. If you find this useful, please ⭐ star the repo!
