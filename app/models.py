from sqlalchemy import Column, Integer, String, Boolean, Numeric, Date, JSON, TIMESTAMP, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base

# Users Table
class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True)
    google_oauth = Column(Boolean, default=False)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    name = Column(String)

# Tests Table
class Test(Base):
    __tablename__ = "tests"

    test_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id"))
    test_date = Column(Date)
    test_status = Column(String)  # USER-DEFINED type as string
    test_name = Column(String)

# Test Configurations Table
class TestConfiguration(Base):
    __tablename__ = "test_configurations"

    config_id = Column(Integer, primary_key=True, index=True)
    test_id = Column(Integer, ForeignKey("tests.test_id"))
    config_date = Column(Date)
    status = Column(String)  # USER-DEFINED type as string
    options = Column(JSON)
    config_name = Column(String)

# Target Details Table
class TargetDetail(Base):
    __tablename__ = "target_details"

    target_id = Column(Integer, primary_key=True, index=True)
    test_id = Column(Integer, ForeignKey("tests.test_id"))
    injection_fields = Column(JSON)
    url_target = Column(String)
    auth_email = Column(String)
    auth_password = Column(String)

# Vulnerabilities Table
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    vulnerability_id = Column(Integer, primary_key=True, index=True)
    test_id = Column(Integer, ForeignKey("tests.test_id"))
    cvss_score = Column(Numeric)
    potential_loss = Column(Numeric)
    severity = Column(String)  # USER-DEFINED type as string
    endpoint = Column(String)
    vulnerability_name = Column(String)

# Suggestions Table
class Suggestion(Base):
    __tablename__ = "suggestions"

    suggestion_id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.vulnerability_id"))
    roi = Column(Numeric)
    suggestion_text = Column(String)

# Reports Table
class Report(Base):
    __tablename__ = "reports"

    report_id = Column(Integer, primary_key=True, index=True)
    test_id = Column(Integer, ForeignKey("tests.test_id"))
    report_date = Column(TIMESTAMP)
    vulnerability_count = Column(Integer)
    compliance_score = Column(Numeric)
    compliance_date = Column(Date)
    risk_score = Column(Numeric)
    framework_name = Column(String)
    summary = Column(String)
    detailed_findings = Column(String)
