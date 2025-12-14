# XeraSentry v4.0 - Complete Production Version
# Blockchain Security Monitoring System

import json
import hashlib
import time
import os
import sqlite3
import logging
import signal
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Callable, Set
from enum import Enum
from collections import defaultdict, deque
from abc import ABC, abstractmethod
from web3 import Web3
from web3.exceptions import BlockNotFound, TransactionNotFound
import requests

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('blockchain_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Custom Exceptions
class BlockchainError(Exception):
    """Base exception for blockchain errors"""
    pass

class RPCConnectionError(BlockchainError):
    """RPC connection failed"""
    def __init__(self, message: str, endpoint: str = None, original_error: Exception = None):
        self.endpoint = endpoint
        self.original_error = original_error
        super().__init__(f"{message} (endpoint: {endpoint})" if endpoint else message)

class ValidationError(BlockchainError):
    """Invalid input data"""
    pass

# Configuration
class Config:
    """Configuration with environment variable support"""
    
    RPC_URLS = {
        'ethereum': [
            'https://eth.llamarpc.com',
            'https://rpc.ankr.com/eth',
            'https://ethereum.publicnode.com',
        ],
        'sepolia': [
            'https://rpc.sepolia.org',
            'https://ethereum-sepolia.publicnode.com',
        ],
    }
    
    HIGH_VALUE_THRESHOLD = float(os.getenv('HIGH_VALUE_THRESHOLD', '0.65'))
    WHALE_THRESHOLD = float(os.getenv('WHALE_THRESHOLD', '50'))
    EXTREME_GAS_THRESHOLD = float(os.getenv('EXTREME_GAS_THRESHOLD', '100'))
    MAX_HISTORY_BLOCKS = int(os.getenv('MAX_HISTORY_BLOCKS', '100'))
    MAX_TX_DEDUP_CACHE = int(os.getenv('MAX_TX_DEDUP_CACHE', '10000'))
    RATE_LIMIT_DELAY = float(os.getenv('RATE_LIMIT_DELAY', '0.1'))
    MAX_RETRY_ATTEMPTS = int(os.getenv('MAX_RETRY_ATTEMPTS', '3'))
    
    GOOGLE_SHEETS_URL = os.getenv('GOOGLE_SHEETS_URL', '')
    WEBHOOK_URLS = os.getenv('WEBHOOK_URLS', '').split(',') if os.getenv('WEBHOOK_URLS') else []
    
    WATCHED_ADDRESSES = []
    
    STABLECOIN_CONTRACTS = {
        '0xdac17f958d2ee523a2206206994597c13d831ec7': 'USDT',
        '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': 'USDC',
        '0x6b175474e89094c44da98b954eedeac495271d0f': 'DAI',
    }
    
    DEX_ROUTERS = {
        '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': 'Uniswap V2',
        '0xe592427a0aece92de3edee1f18e0157c05861564': 'Uniswap V3',
    }
    
    SANCTIONED_ADDRESSES = [
        '0x8589427373d6d84e98730d7795d8f6f8731fda16',
        '0x722122df12d4e14e13ac3b6895a86e84145b6967',
    ]
    
    MIXER_CONTRACTS = {
        '0xd90e2f925da726b50c4ed8d0fb90ad053324f31b': 'Tornado Cash 0.1 ETH',
        '0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936': 'Tornado Cash 1 ETH',
    }
    
    SAVE_RESULTS = True
    RESULTS_FILE = 'security_alerts.json'
    DB_FILE = 'alerts.db'

config = Config()

# Data Models
class AlertSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    def to_emoji(self) -> str:
        return {1: "🟢", 2: "🟡", 3: "🟠", 4: "🔴"}[self.value]

@dataclass
class Transaction:
    tx_hash: str
    block_number: int
    timestamp: datetime
    from_address: str
    to_address: str
    value: float
    chain_id: str
    gas_used: int = 0
    metadata: Dict = field(default_factory=dict)

@dataclass
class Alert:
    id: str
    timestamp: datetime
    severity: AlertSeverity
    source: str
    rule_id: str
    rule_name: str
    message: str
    transaction: Transaction
    details: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity.name,
            'source': self.source,
            'rule_name': self.rule_name,
            'message': self.message,
            'tx_hash': self.transaction.tx_hash,
            'from': self.transaction.from_address,
            'to': self.transaction.to_address,
            'value': self.transaction.value,
            'block': self.transaction.block_number,
            'details': self.details
        }

@dataclass
class PerformanceMetrics:
    total_transactions: int = 0
    total_alerts: int = 0
    analysis_time: float = 0.0
    rpc_calls: int = 0
    rpc_failures: int = 0
    
    def avg_analysis_time(self) -> float:
        return self.analysis_time / self.total_transactions if self.total_transactions > 0 else 0

# Utility Functions
def validate_address(address: str) -> str:
    if not address or len(address) < 42:
        raise ValidationError(f"Invalid address length: {address}")
    if not address.startswith('0x'):
        address = '0x' + address
    if not all(c in '0123456789abcdefABCDEFx' for c in address):
        raise ValidationError(f"Invalid characters in address: {address}")
    return address.lower()

def health_check() -> Dict:
    try:
        connector = RobustBlockchainConnector('ethereum')
        current_block = connector.w3.eth.block_number
        return {
            'status': 'healthy',
            'connected': True,
            'current_block': current_block,
            'rpc_endpoint': connector.rpc_endpoints[connector.current_endpoint_idx],
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'connected': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

# Database
class AlertDatabase:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or config.DB_FILE
        self.conn = sqlite3.connect(self.db_path)
        self._create_tables()
        logger.info(f"Database initialized: {self.db_path}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def _create_tables(self):
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                message TEXT,
                tx_hash TEXT NOT NULL,
                from_address TEXT,
                to_address TEXT,
                value REAL,
                block_number INTEGER,
                chain_id TEXT,
                details TEXT
            )
        ''')
        
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_from_addr ON alerts(from_address)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_to_addr ON alerts(to_address)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_block ON alerts(block_number)')
        
        self.conn.commit()
    
    def save_alert(self, alert: Alert):
        try:
            with self.conn:
                self.conn.execute('''
                    INSERT OR REPLACE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert.id,
                    alert.timestamp.isoformat(),
                    alert.severity.name,
                    alert.rule_name,
                    alert.message,
                    alert.transaction.tx_hash,
                    alert.transaction.from_address,
                    alert.transaction.to_address,
                    alert.transaction.value,
                    alert.transaction.block_number,
                    alert.transaction.chain_id,
                    json.dumps(alert.details)
                ))
        except Exception as e:
            logger.error(f"Failed to save alert: {e}")
    
    def save_alerts_batch(self, alerts: List[Alert]):
        try:
            with self.conn:
                self.conn.executemany('''
                    INSERT OR REPLACE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', [
                    (a.id, a.timestamp.isoformat(), a.severity.name, a.rule_name,
                     a.message, a.transaction.tx_hash, a.transaction.from_address,
                     a.transaction.to_address, a.transaction.value,
                     a.transaction.block_number, a.transaction.chain_id,
                     json.dumps(a.details))
                    for a in alerts
                ])
            logger.info(f"Saved {len(alerts)} alerts in batch")
        except Exception as e:
            logger.error(f"Failed to save alerts batch: {e}")
    
    def get_recent_alerts(self, limit: int = 100) -> List[Dict]:
        cursor = self.conn.execute(
            'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        return [dict(zip([col[0] for col in cursor.description], row)) 
                for row in cursor.fetchall()]
    
    def close(self):
        self.conn.close()

# Google Sheets Integration
class GoogleSheetsNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        logger.info("Google Sheets notifier initialized")
    
    def send_alert(self, alert: Alert):
        try:
            payload = {
                'timestamp': alert.timestamp.isoformat(),
                'severity': alert.severity.name,
                'rule_name': alert.rule_name,
                'message': alert.message,
                'tx_hash': alert.transaction.tx_hash,
                'from': alert.transaction.from_address,
                'to': alert.transaction.to_address,
                'value': alert.transaction.value,
                'block': alert.transaction.block_number
            }
            
            response = requests.post(
                self.webhook_url,
                headers={'Content-Type': 'application/json'},
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info(f"✅ Alert sent to Google Sheets")
                return True
            else:
                logger.error(f"❌ Google Sheets error: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send to Google Sheets: {e}")
            return False

# Detection Rules
class DetectionRule(ABC):
    @abstractmethod
    def detect(self, tx: Transaction, context: Dict) -> List[Alert]:
        pass
    
    @property
    @abstractmethod
    def rule_id(self) -> str:
        pass
    
    @property
    @abstractmethod
    def severity(self) -> AlertSeverity:
        pass

class HighValueRule(DetectionRule):
    def __init__(self, threshold: float = None):
        self.threshold = threshold or config.HIGH_VALUE_THRESHOLD
    
    @property
    def rule_id(self) -> str:
        return 'high_value'
    
    @property
    def severity(self) -> AlertSeverity:
        return AlertSeverity.HIGH
    
    def detect(self, tx: Transaction, context: Dict) -> List[Alert]:
        if tx.value > self.threshold:
            return [Alert(
                id=hashlib.sha256(f"{tx.tx_hash}:{self.rule_id}".encode()).hexdigest()[:12],
                timestamp=datetime.now(),
                severity=self.severity,
                source='rules',
                rule_id=self.rule_id,
                rule_name='High Value Transfer',
                message=f"Transfer of {tx.value:.2f} ETH detected",
                transaction=tx,
                details={'threshold': self.threshold}
            )]
        return []

class WhaleRule(DetectionRule):
    def __init__(self, threshold: float = None):
        self.threshold = threshold or config.WHALE_THRESHOLD
    
    @property
    def rule_id(self) -> str:
        return 'whale_transfer'
    
    @property
    def severity(self) -> AlertSeverity:
        return AlertSeverity.CRITICAL
    
    def detect(self, tx: Transaction, context: Dict) -> List[Alert]:
        if tx.value > self.threshold:
            return [Alert(
                id=hashlib.sha256(f"{tx.tx_hash}:{self.rule_id}".encode()).hexdigest()[:12],
                timestamp=datetime.now(),
                severity=self.severity,
                source='rules',
                rule_id=self.rule_id,
                rule_name='WHALE TRANSFER',
                message=f"🐋 MASSIVE {tx.value:.2f} ETH transfer",
                transaction=tx,
                details={'threshold': self.threshold}
            )]
        return []

class SanctionedAddressRule(DetectionRule):
    @property
    def rule_id(self) -> str:
        return 'sanctioned'
    
    @property
    def severity(self) -> AlertSeverity:
        return AlertSeverity.CRITICAL
    
    def detect(self, tx: Transaction, context: Dict) -> List[Alert]:
        alerts = []
        if tx.to_address in config.SANCTIONED_ADDRESSES:
            alerts.append(Alert(
                id=hashlib.sha256(f"{tx.tx_hash}:sanc_to".encode()).hexdigest()[:12],
                timestamp=datetime.now(),
                severity=self.severity,
                source='compliance',
                rule_id=self.rule_id,
                rule_name='SANCTIONED ADDRESS',
                message=f"⛔ Transaction TO sanctioned address",
                transaction=tx
            ))
        return alerts

class WatchedAddressRule(DetectionRule):
    @property
    def rule_id(self) -> str:
        return 'watched_activity'
    
    @property
    def severity(self) -> AlertSeverity:
        return AlertSeverity.MEDIUM
    
    def detect(self, tx: Transaction, context: Dict) -> List[Alert]:
        alerts = []
        if tx.from_address in config.WATCHED_ADDRESSES:
            alerts.append(Alert(
                id=hashlib.sha256(f"{tx.tx_hash}:{self.rule_id}".encode()).hexdigest()[:12],
                timestamp=datetime.now(),
                severity=AlertSeverity.HIGH if tx.value > 10 else self.severity,
                source='watched',
                rule_id=self.rule_id,
                rule_name='Watched Address Activity',
                message=f"👁️ OUTGOING: {tx.value:.4f} ETH from {tx.from_address[:12]}...",
                transaction=tx
            ))
        elif tx.to_address in config.WATCHED_ADDRESSES:
            alerts.append(Alert(
                id=hashlib.sha256(f"{tx.tx_hash}:{self.rule_id}".encode()).hexdigest()[:12],
                timestamp=datetime.now(),
                severity=AlertSeverity.HIGH if tx.value > 10 else self.severity,
                source='watched',
                rule_id=self.rule_id,
                rule_name='Watched Address Activity',
                message=f"👁️ INCOMING: {tx.value:.4f} ETH to {tx.to_address[:12]}...",
                transaction=tx
            ))
        return alerts

# Blockchain Connector
class RobustBlockchainConnector:
    def __init__(self, chain: str = 'ethereum'):
        self.chain = chain
        self.rpc_endpoints = config.RPC_URLS.get(chain, [])
        self.current_endpoint_idx = 0
        self.w3: Optional[Web3] = None
        self.metrics = PerformanceMetrics()
        self.endpoint_last_call = defaultdict(float)
        self._connect()
    
    def _connect(self):
        for idx in range(len(self.rpc_endpoints)):
            endpoint = self.rpc_endpoints[self.current_endpoint_idx]
            try:
                self.w3 = Web3(Web3.HTTPProvider(endpoint, request_kwargs={'timeout': 30}))
                if self.w3.is_connected():
                    logger.info(f"✅ Connected to {self.chain} via {endpoint}")
                    print(f"✅ Connected to {self.chain}")
                    print(f"📍 Current block: {self.w3.eth.block_number}\n")
                    return
            except Exception as e:
                logger.warning(f"Failed to connect to {endpoint}: {e}")
                self.current_endpoint_idx = (self.current_endpoint_idx + 1) % len(self.rpc_endpoints)
        raise RPCConnectionError(f"Failed to connect to {self.chain}")
    
    def get_transactions(self, num_blocks: int = 1) -> List[Transaction]:
        transactions = []
        try:
            current_block = self.w3.eth.block_number
        except Exception as e:
            logger.error(f"Failed to get current block: {e}")
            return []
        
        print(f"🔍 Fetching from {num_blocks} block(s)...")
        
        for block_num in range(current_block - num_blocks + 1, current_block + 1):
            try:
                time.sleep(config.RATE_LIMIT_DELAY)
                block = self.w3.eth.get_block(block_num, full_transactions=True)
                
                for tx in block.transactions:
                    try:
                        transactions.append(Transaction(
                            tx_hash=tx.hash.hex(),
                            block_number=block_num,
                            timestamp=datetime.fromtimestamp(block.timestamp),
                            from_address=tx['from'].lower(),
                            to_address=(tx['to'] or '0x0_contract').lower(),
                            value=float(self.w3.from_wei(tx['value'], 'ether')),
                            chain_id=self.chain,
                            gas_used=tx['gas'],
                            metadata={
                                'gas_price_gwei': float(self.w3.from_wei(tx['gasPrice'], 'gwei')),
                                'nonce': tx['nonce'],
                            }
                        ))
                    except Exception:
                        continue
            except Exception as e:
                logger.error(f"Error fetching block {block_num}: {e}")
                continue
        
        print(f"✅ Fetched {len(transactions)} transactions\n")
        return transactions

# Security Engine
class ModularSecurityEngine:
    def __init__(self, google_sheets_url: Optional[str] = None):
        self.rules: List[DetectionRule] = []
        self.alerts: List[Alert] = []
        self.tx_count = 0
        self.session_start = datetime.now()
        self.metrics = PerformanceMetrics()
        self.seen_tx_hashes: Set[str] = set()
        
        self.tx_by_block: Dict[int, List[Transaction]] = {}
        self.tx_by_address = defaultdict(lambda: deque(maxlen=100))
        self.block_order = deque(maxlen=config.MAX_HISTORY_BLOCKS)
        
        self.db = AlertDatabase()
        
        # Google Sheets
        sheets_url = google_sheets_url or config.GOOGLE_SHEETS_URL
        self.sheets_notifier = GoogleSheetsNotifier(sheets_url) if sheets_url else None
        
        self._load_default_rules()
    
    def _load_default_rules(self):
        self.add_rule(HighValueRule())
        self.add_rule(WhaleRule())
        self.add_rule(SanctionedAddressRule())
        self.add_rule(WatchedAddressRule())
        logger.info(f"Loaded {len(self.rules)} detection rules")
    
    def add_rule(self, rule: DetectionRule):
        self.rules.append(rule)
    
    def analyze(self, tx: Transaction) -> List[Alert]:
        if tx.tx_hash in self.seen_tx_hashes:
            return []
        
        self.seen_tx_hashes.add(tx.tx_hash)
        if len(self.seen_tx_hashes) > config.MAX_TX_DEDUP_CACHE:
            self.seen_tx_hashes = set(list(self.seen_tx_hashes)[-5000:])
        
        self.tx_count += 1
        new_alerts = []
        
        context = {'tx_by_block': self.tx_by_block}
        
        for rule in self.rules:
            try:
                alerts = rule.detect(tx, context)
                new_alerts.extend(alerts)
            except Exception as e:
                logger.error(f"Rule {rule.rule_id} failed: {e}")
        
        # Save to database
        for alert in new_alerts:
            self.db.save_alert(alert)
        
        # Send to Google Sheets
        if self.sheets_notifier:
            for alert in new_alerts:
                self.sheets_notifier.send_alert(alert)
        
        self.metrics.total_transactions += 1
        self.metrics.total_alerts += len(new_alerts)
        self.alerts.extend(new_alerts)
        return new_alerts
    
    def print_summary(self):
        print(f"\n{'='*70}")
        print("📊 SESSION SUMMARY")
        print(f"{'='*70}")
        print(f"📦 Transactions analyzed: {self.tx_count}")
        print(f"🚨 Total alerts: {len(self.alerts)}")
        
        if self.alerts:
            by_severity = defaultdict(int)
            for a in self.alerts:
                by_severity[a.severity.name] += 1
            
            print(f"\n📈 By Severity:")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if sev in by_severity:
                    print(f"   {AlertSeverity[sev].to_emoji()} {sev}: {by_severity[sev]}")
        
        print(f"{'='*70}\n")
    
    def close(self):
        self.db.close()

# Main Functions
def monitor(chain: str = 'ethereum', num_blocks: int = 1, max_tx: int = 20) -> Optional[ModularSecurityEngine]:
    print(f"\n{'='*70}")
    print(f"🛡️  XERASENTRY BLOCKCHAIN SECURITY")
    print(f"{'='*70}\n")
    
    try:
        connector = RobustBlockchainConnector(chain)
        txs = connector.get_transactions(num_blocks)
        
        if not txs:
            print("❌ No transactions found")
            return None
        
        engine = ModularSecurityEngine()
        analyze_count = min(len(txs), max_tx)
        
        print(f"🔬 Analyzing {analyze_count} of {len(txs)} transactions...\n")
        
        for i, tx in enumerate(txs[:max_tx], 1):
            alerts = engine.analyze(tx)
            
            if alerts:
                print(f"🚨 ALERT #{i}")
                print(f"📦 TX: {tx.tx_hash[:24]}...")
                for alert in alerts:
                    print(f"   {alert.severity.to_emoji()} [{alert.severity.name}] {alert.message}")
                print()
        
        engine.print_summary()
        return engine
        
    except Exception as e:
        logger.error(f"Monitoring failed: {e}")
        print(f"❌ Error: {e}")
        return None

def quick_scan():
    """Quick scan - 1 block, 20 transactions"""
    return monitor(chain='ethereum', num_blocks=1, max_tx=20)

def deep_scan():
    """Deep scan - 3 blocks, 50 transactions"""
    return monitor(chain='ethereum', num_blocks=3, max_tx=50)

def watch_address(address: str, num_blocks: int = 2):
    """Monitor specific address"""
    try:
        address = validate_address(address)
    except ValidationError as e:
        print(f"❌ {e}")
        return None
    
    original = config.WATCHED_ADDRESSES.copy()
    config.WATCHED_ADDRESSES.append(address)
    
    print(f"\n👁️  Monitoring: {address}\n")
    engine = monitor(chain='ethereum', num_blocks=num_blocks, max_tx=50)
    
    config.WATCHED_ADDRESSES = original
    return engine

# Initialize
print("""
✅ XeraSentry v4.0 Ready!

🚀 COMMANDS:
  quick_scan()              # Scan 1 block
  deep_scan()               # Scan 3 blocks
  watch_address('0x123...')  # Monitor address
  health_check()            # System status

📊 Alerts save to:
  • Local database (alerts.db)
  • Google Sheets (if configured)

💡 Configure .env file for Google Sheets integration
""")