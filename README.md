# Cyber Defense System

A comprehensive cyber defense system that monitors, analyzes, and responds to security threats in real-time. The system uses a multi-layered approach with perception, prediction, decision-making, and automated response capabilities.

## Architecture

The system is built with the following modules:

### 🧠 Perception Layer (`perception/`)
- **Behavior Analysis**: Analyzes raw entity telemetry to compute behavior scores and anomaly levels
- **Input**: Connection rates, authentication patterns, port scanning, resource access
- **Output**: Behavior profiles with risk scores [0-100] and anomaly levels

### 🔮 Prediction Layer (`prediction/`)
- **Attack Prediction**: Predicts current and next attack stages based on behavior analysis
- **Attack Stages**: normal → reconnaissance → initial_access → lateral_movement → privilege_escalation → data_exfiltration
- **Output**: Attack stage predictions with confidence scores

### ⚖️ Decision Engine (`decision_engine/`)
- **Security Decisions**: Makes automated security decisions based on multiple factors
- **Actions**: monitor, alert, block, isolate
- **Factors**: Behavior score, attack stage, trust score, confidence levels

### 🛡️ Trust System (`trust_system/`)
- **Trust Management**: Maintains dynamic trust scores for entities
- **Features**: Time-based decay, historical patterns, positive/negative reinforcement
- **Risk Levels**: low, medium, high, critical

### 🚨 Response Engine (`response/`)
- **Automated Responses**: Executes security decisions automatically
- **Response Types**: Enhanced monitoring, security alerts, network blocking, system isolation
- **Tracking**: Complete response history with status and timing

### 📊 Dashboard (`dashboard/`)
- **Real-time Monitoring**: Command-line dashboard for system visualization
- **Features**: System overview, risk distribution, active responses, high-risk entities
- **Auto-refresh**: Updates every 5 seconds

## Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Dependencies
```bash
pip install pytest
```

### Running the System

#### 1. Main Application (Demo Mode)
```bash
python main.py
```
This runs a demonstration scenario with three test entities showing different behavior patterns.

#### 2. Interactive Mode
```bash
python main.py
# Choose option 2 for interactive mode
```
Allows manual input of entity data for analysis.

#### 3. Run Tests
```bash
python -m pytest tests/ -v
```
Runs all unit tests to verify system functionality.

#### 4. Dashboard
```bash
python dashboard/dashboard_simple.py
```
Starts the real-time monitoring dashboard (press Ctrl+C to exit).

## System Features

### Behavior Analysis
- **Connection Rate Monitoring**: Tracks connection patterns and request frequencies
- **Authentication Analysis**: Monitors failed vs successful authentication attempts
- **Port Scanning Detection**: Identifies reconnaissance activities
- **Resource Access Tracking**: Monitors access to sensitive resources

### Attack Prediction
- **Stage-based Prediction**: Maps behavior to attack lifecycle stages
- **Confidence Scoring**: Provides confidence levels for predictions
- **Progression Tracking**: Predicts next likely attack stage

### Automated Decision Making
- **Multi-factor Analysis**: Combines behavior, prediction, and trust data
- **Risk-based Actions**: Scales responses based on threat level
- **Explainable Decisions**: Provides reasoning for all security decisions

### Trust Management
- **Dynamic Scoring**: Updates trust scores based on entity behavior
- **Historical Context**: Considers past behavior patterns
- **Time Decay**: Automatically adjusts scores over time
- **Trend Analysis**: Tracks improving or declining trust patterns

### Response Automation
- **Immediate Response**: Executes security actions without human intervention
- **Response Tracking**: Maintains complete audit trail of all actions
- **Status Monitoring**: Tracks execution status and completion

## Example Usage

### Basic Entity Analysis
```python
from perception.behavior_analysis import analyze_behavior
from prediction.attack_prediction import predict_attack
from decision_engine.descision_engine import make_decision
from trust_system.trust_manager import update_trust_score
from response.engine import execute_response

# Analyze entity behavior
entity_data = {
    'connection_rate': 0.8,
    'request_rate': 0.9,
    'failed_auth_count': 15,
    'total_auth_count': 20,
    'unique_ports': 0.9,
    'sensitive_access_count': 0.7
}

# Process through the pipeline
behavior_profile = analyze_behavior(entity_data)
attack_prediction = predict_attack(behavior_profile)
trust_score = update_trust_score('entity_001', behavior_profile.behavior_score)
decision = make_decision(behavior_profile, attack_prediction, trust_score)

# Execute response if needed
if decision['action'] != 'monitor':
    response = execute_response('entity_001', decision)
    print(f"Response executed: {response['status']}")
```

## Testing

The system includes comprehensive unit tests:

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test modules
python -m pytest tests/test_perception_behavior.py -v
python -m pytest tests/test_prediction_attack.py -v
```

## Configuration

### Trust System Parameters
- `max_history_length`: Number of behavior scores to keep (default: 20)
- `decay_rate`: Daily trust decay factor (default: 0.95)
- `positive_boost`: Trust boost for good behavior (default: 2.0)
- `negative_penalty`: Trust penalty for bad behavior (default: 5.0)

### Decision Engine Thresholds
- **Isolation**: behavior_score ≥ 85 OR critical attack stages OR trust_score < 20
- **Block**: behavior_score ≥ 70 OR lateral_movement OR trust_score < 40
- **Alert**: behavior_score ≥ 50 OR initial_access OR trust_score < 60
- **Monitor**: All other cases

## Security Considerations

- **False Positives**: The system uses conservative thresholds to minimize false positives
- **Response Safety**: All responses are logged and can be cancelled if needed
- **Trust Recovery**: Trust scores can be reset for false positive recovery
- **Audit Trail**: Complete logging of all decisions and responses

## Future Enhancements

- Machine learning integration for improved prediction accuracy
- Web-based dashboard with real-time updates
- Integration with external security tools (SIEM, IDS/IPS)
- Advanced anomaly detection algorithms
- Multi-tenant support
- API endpoints for external integration

## License

This project is part of a cyber defense system demonstration. Use responsibly and in accordance with applicable laws and regulations.

## Contributing

When contributing to this project:
1. Ensure all tests pass
2. Follow the existing code style
3. Add appropriate documentation
4. Consider security implications of changes

## Support

For issues or questions regarding the cyber defense system, please refer to the documentation or create appropriate issues in the project repository.
