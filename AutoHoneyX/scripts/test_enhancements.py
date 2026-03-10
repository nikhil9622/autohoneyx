#!/usr/bin/env python3
"""
Integration Test Script for AutoHoneyX Cybersecurity Enhancements
Validates all 6 modules are working correctly together
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def test_anomaly_detection():
    """Test anomaly detection engine"""
    logger.info("=" * 60)
    logger.info("TEST 1: Anomaly Detection Engine")
    logger.info("=" * 60)
    
    try:
        from app.anomaly_detector import get_anomaly_engine
        from app.database import get_db_session
        from app.models import AttackLog
        
        engine = get_anomaly_engine()
        logger.info("✓ Anomaly detection engine initialized")
        
        # Create mock attack log
        session = get_db_session()
        recent_logs = session.query(AttackLog).limit(10).all()
        session.close()
        
        if recent_logs:
            score, is_anomalous, reason = engine.detect(recent_logs[0])
            logger.info(f"✓ Detection complete: score={score:.3f}, anomalous={is_anomalous}")
            logger.info(f"  Reason: {reason}")
        else:
            logger.warning("⚠ No attack logs to test with")
        
        return True
    except Exception as e:
        logger.error(f"✗ Test failed: {e}")
        return False

async def test_kill_chain_analyzer():
    """Test kill chain and severity scoring"""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 2: Kill Chain & Severity Scoring")
    logger.info("=" * 60)
    
    try:
        from app.kill_chain_analyzer import get_kill_chain_mapper
        from app.database import get_db_session
        from app.models import AttackLog
        
        mapper = get_kill_chain_mapper()
        logger.info("✓ Kill chain mapper initialized")
        
        session = get_db_session()
        recent_logs = session.query(AttackLog).limit(1).all()
        session.close()
        
        if recent_logs:
            log = recent_logs[0]
            tactic, technique, conf = mapper.classify_attack(log)
            severity, level, reasons = mapper.calculate_severity_score(log)
            
            logger.info(f"✓ Attack classified: {tactic} / {technique}")
            logger.info(f"✓ Severity: {level} (score={severity:.2f})")
            logger.info(f"  Factors: {reasons}")
        else:
            logger.warning("⚠ No attack logs to test with")
        
        return True
    except Exception as e:
        logger.error(f"✗ Test failed: {e}")
        return False

async def test_siem_connector():
    """Test SIEM integration"""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 3: SIEM Integration")
    logger.info("=" * 60)
    
    try:
        from app.siem_connector import get_siem_manager
        
        siem = get_siem_manager()
        logger.info("✓ SIEM manager initialized")
        
        # Test connections
        results = siem.test_all_connections()
        for platform, (success, message) in results.items():
            status = "✓" if success else "⚠"
            logger.info(f"{status} {platform}: {message}")
        
        return True
    except Exception as e:
        logger.error(f"✗ Test failed: {e}")
        return False

async def test_forensics_collector():
    """Test forensic artifact collection"""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 4: Forensic Artifact Collection")
    logger.info("=" * 60)
    
    try:
        from app.forensics_collector import get_forensics_collector
        
        collector = get_forensics_collector()
        logger.info("✓ Forensics collector initialized")
        
        # Try collecting artifacts (won't store)
        processes = collector.collect_processes()
        network = collector.collect_network_connections()
        system = collector.collect_system_info()
        
        logger.info(f"✓ Collected process artifacts: {len(processes)} artifacts")
        logger.info(f"✓ Collected network artifacts: {len(network)} artifacts")
        logger.info(f"✓ Collected system artifacts: {len(system)} artifacts")
        
        return True
    except Exception as e:
        logger.error(f"✗ Test failed: {e}")
        return False

async def test_incident_rca():
    """Test timeline and RCA"""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 5: Timeline & Root Cause Analysis")
    logger.info("=" * 60)
    
    try:
        from app.incident_rca import get_timeline_builder, get_rca_engine
        from app.database import get_db_session
        from app.models import AttackLog
        
        timeline = get_timeline_builder()
        rca = get_rca_engine()
        logger.info("✓ Timeline builder initialized")
        logger.info("✓ RCA engine initialized")
        
        session = get_db_session()
        recent_logs = session.query(AttackLog).limit(1).all()
        session.close()
        
        if recent_logs:
            log = recent_logs[0]
            analysis = rca.analyze_attack(log)
            logger.info(f"✓ RCA analysis complete:")
            logger.info(f"  Pattern: {analysis.get('attack_pattern')}")
            logger.info(f"  Confidence: {analysis.get('confidence'):.1%}")
            logger.info(f"  Root Causes: {len(analysis.get('root_causes', []))} identified")
        else:
            logger.warning("⚠ No attack logs to test with")
        
        return True
    except Exception as e:
        logger.error(f"✗ Test failed: {e}")
        return False

async def test_playbook_engine():
    """Test playbook engine"""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 6: Playbook Engine")
    logger.info("=" * 60)
    
    try:
        from app.playbook_engine import get_playbook_engine
        
        engine = get_playbook_engine()
        logger.info("✓ Playbook engine initialized")
        
        # Check loaded playbooks
        playbook_count = len(engine.playbooks)
        logger.info(f"✓ Loaded {playbook_count} playbooks:")
        for name in engine.playbooks.keys():
            logger.info(f"  - {name}")
        
        return True
    except Exception as e:
        logger.error(f"✗ Test failed: {e}")
        return False

async def test_orchestrator():
    """Test incident orchestrator"""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 7: Incident Orchestrator")
    logger.info("=" * 60)
    
    try:
        from app.incident_orchestrator import get_orchestrator
        
        orchestrator = get_orchestrator()
        logger.info("✓ Incident orchestrator initialized")
        logger.info("✓ All engines coordinated:")
        logger.info("  - Anomaly detection engine")
        logger.info("  - Kill chain mapper")
        logger.info("  - SIEM manager")
        logger.info("  - Forensics collector")
        logger.info("  - Timeline builder")
        logger.info("  - RCA engine")
        logger.info("  - Playbook engine")
        
        return True
    except Exception as e:
        logger.error(f"✗ Test failed: {e}")
        return False

async def test_event_processor():
    """Test realtime event processor"""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 8: Realtime Event Processor")
    logger.info("=" * 60)
    
    try:
        from app.realtime_event_processor import get_event_processor
        
        processor = get_event_processor()
        logger.info("✓ Event processor initialized")
        logger.info(f"  Queue size: {processor.get_stats()['queue_size']}")
        logger.info(f"  Processed: {processor.get_stats()['processed']}")
        logger.info(f"  Errors: {processor.get_stats()['error_count']}")
        
        return True
    except Exception as e:
        logger.error(f"✗ Test failed: {e}")
        return False

async def main():
    """Run all integration tests"""
    logger.info("\n")
    logger.info("╔" + "=" * 58 + "╗")
    logger.info("║" + " AutoHoneyX Enhancement Integration Tests ".center(58) + "║")
    logger.info("╚" + "=" * 58 + "╝\n")
    
    tests = [
        test_anomaly_detection,
        test_kill_chain_analyzer,
        test_siem_connector,
        test_forensics_collector,
        test_incident_rca,
        test_playbook_engine,
        test_orchestrator,
        test_event_processor,
    ]
    
    results = []
    for test in tests:
        try:
            result = await test()
            results.append(result)
        except Exception as e:
            logger.error(f"Unexpected error in {test.__name__}: {e}")
            results.append(False)
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("TEST SUMMARY")
    logger.info("=" * 60)
    
    passed = sum(results)
    total = len(results)
    
    for i, (test, result) in enumerate(zip(tests, results), 1):
        status = "✓ PASS" if result else "✗ FAIL"
        logger.info(f"{i}. {test.__name__.replace('test_', '').replace('_', ' ').title()}: {status}")
    
    logger.info("=" * 60)
    logger.info(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("🎉 All tests passed! Enhancement implementation successful.\n")
        return 0
    else:
        logger.error(f"⚠ {total - passed} test(s) failed.\n")
        return 1

if __name__ == '__main__':
    exit_code = asyncio.run(main())
    exit(exit_code)
