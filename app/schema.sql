
-- Table: users
user_id integer,
google_oauth boolean,
email character varying,
password character varying,
name character varying,

-- Table: tests
test_id integer,
user_id integer,
test_date date,
test_status USER-DEFINED,
test_name character varying,

-- Table: test_configurations
config_id integer,
test_id integer,
config_date date,
status USER-DEFINED,
options json,
config_name character varying,

-- Table: target_details
target_id integer,
test_id integer,
injection_fields json,
url_target character varying,
auth_email character varying,
auth_password character varying,

-- Table: vulnerabilities
cvss_score numeric,
potential_loss numeric,
test_id integer,
vulnerability_id integer,
severity USER-DEFINED,
endpoint character varying,
vulnerability_name character varying,

-- Table: suggestions
suggestion_id integer,
vulnerability_id integer,
roi numeric,
suggestion_text text,

-- Table: reports
report_date timestamp without time zone,
test_id integer,
vulnerability_count integer,
compliance_score numeric,
compliance_date date,
risk_score numeric,
report_id integer,
framework_name character varying,
summary text,
detailed_findings text,
