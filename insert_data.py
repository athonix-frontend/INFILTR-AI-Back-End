import psycopg2
from psycopg2 import sql
from datetime import datetime
import json

# Database connection parameters
DB_HOST = "172.235.38.75"
DB_NAME = "mydatabase"
DB_USER = "postgres"
DB_PASS = "postgres"

def insert_data():
    try:
        # Connect to PostgreSQL database
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS
        )
        conn.autocommit = True  # ✅ Ensures data is committed automatically
        cur = conn.cursor()

        # Confirm database connection and user
        cur.execute("SELECT current_database(), current_user;")
        db_info = cur.fetchone()
        print(f"🔗 Connected to database: {db_info[0]} as user: {db_info[1]}")

        # Check if user_id = 1 exists in the users table
        cur.execute("SELECT user_id FROM users WHERE user_id = 1;")
        user_check = cur.fetchone()
        if not user_check:
            print("⚠️ User with user_id = 1 does not exist. Aborting insert.")
            return {"error": "User with user_id = 1 does not exist."}

        user_id = 1  # Existing user_id

        # Insert into tests table
        test_query = """
            INSERT INTO tests (user_id, test_name, test_date, test_status)
            VALUES (%s, %s, %s, %s)
            RETURNING test_id;
        """
        test_data = (user_id, 'Security Audit', datetime.now().date(), 'Unselected')
        print(f"Executing: {cur.mogrify(test_query, test_data).decode()}")
        cur.execute(test_query, test_data)
        test_id = cur.fetchone()[0]
        print(f"✅ Inserted into tests, test_id = {test_id}")

        # Insert into target_details table
        target_query = """
            INSERT INTO target_details (test_id, url_target, auth_email, auth_password, injection_fields)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING target_id;
        """
        injection_fields = json.dumps({"input1": "test", "input2": "payload"})
        target_data = (test_id, 'http://example.com', 'admin@example.com', 'securepassword', injection_fields)
        print(f"Executing: {cur.mogrify(target_query, target_data).decode()}")
        cur.execute(target_query, target_data)
        print("✅ Inserted into target_details")

        # Insert into vulnerabilities table
        vulnerability_query = """
            INSERT INTO vulnerabilities (test_id, vulnerability_name, endpoint, severity, cvss_score, potential_loss)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING vulnerability_id;
        """
        vulnerability_data = (test_id, 'SQL Injection', '/login', 'High', 9.1, 5000.00)
        print(f"Executing: {cur.mogrify(vulnerability_query, vulnerability_data).decode()}")
        cur.execute(vulnerability_query, vulnerability_data)
        vulnerability_id = cur.fetchone()[0]
        print(f"✅ Inserted into vulnerabilities, vulnerability_id = {vulnerability_id}")

        # Insert into suggestions table
        suggestion_query = """
            INSERT INTO suggestions (vulnerability_id, suggestion_text, roi)
            VALUES (%s, %s, %s);
        """
        suggestion_data = (vulnerability_id, 'Sanitize all user inputs before database queries.', 95.5)
        print(f"Executing: {cur.mogrify(suggestion_query, suggestion_data).decode()}")
        cur.execute(suggestion_query, suggestion_data)
        print("✅ Inserted into suggestions")

        # Insert into reports table
        report_query = """
            INSERT INTO reports (test_id, vulnerability_count, compliance_score, framework_name, compliance_date, risk_score, summary, detailed_findings, report_date)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
        """
        report_data = (
            test_id, 1, 85.0, 'NIST', datetime.now().date(), 70.0,
            'Security audit summary', 'Detailed report with findings and recommendations', datetime.now()
        )
        print(f"Executing: {cur.mogrify(report_query, report_data).decode()}")
        cur.execute(report_query, report_data)
        print("✅ Inserted into reports")

        print("🎉 All data inserted successfully!")
        return {"message": "Data inserted successfully"}

    except Exception as e:
        print(f"❌ An error occurred: {e}")
        conn.rollback()
        return {"error": str(e)}

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
        print("🔒 Database connection closed.")

if __name__ == "__main__":
    insert_data()
