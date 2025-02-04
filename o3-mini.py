#!/Users/austintollennaar/Downloads/INFILTR-AI/Back-End/venv/bin/python
"""
Skeptical Checklist:
- [✔️] Import required modules (requests, json, os, time, subprocess, re, tempfile, logging, sys, datetime, psycopg2)
- [✔️] Set up PostgreSQL DB connection parameters
- [✔️] Define logging (with humorous but clear messages)
- [✔️] Define functions to interact with OpenAI, process scan results, generate pentest scripts, etc.
- [✔️] Append new function to insert structured JSON data into PostgreSQL
- [✔️] In __main__, execute the scan, generate structured JSON output, then insert data into the DB
- [✔️] No sugar-coating: this code is raw and ready to test.
"""

import requests
import json
import os
import time
import subprocess
import re
import tempfile
import logging
import sys
import datetime
import psycopg2
from psycopg2 import sql
from openai import OpenAI

# Database connection parameters for PostgreSQL
DB_HOST = "172.235.38.75"
DB_NAME = "mydatabase"
DB_USER = "postgres"
DB_PASS = "postgres"

# Global context buffers
vulnerability_context_buffer = []  # Stores each discovered vulnerability details
pentest_script_context_buffer = []   # Stores each generated pentest script and its execution results

# NOTE: Remember to use environment variables in production for API keys.
OPENAI_API_KEY = "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"
client = OpenAI(api_key=OPENAI_API_KEY)

def setup_logging():
    """
    [✓] Configures logging: console and file output.
         Because logging is like a diary – it tells you the truth, whether you like it or not.
    """
    logger = logging.getLogger('GPT_Script')
    logger.setLevel(logging.DEBUG)

    # Create handlers
    c_handler = logging.StreamHandler(sys.stdout)
    f_handler = logging.FileHandler('GPT.log')

    c_handler.setLevel(logging.INFO)
    f_handler.setLevel(logging.DEBUG)

    # Create formatters
    c_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    f_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Add formatters to handlers
    c_handler.setFormatter(c_format)
    f_handler.setFormatter(f_format)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)

    return logger

logger = setup_logging()

def strip_code_fences(text):
    """
    [✓] Removes code fences (e.g., ```json) from the response text if present.
    """
    logger.debug("Stripping code fences from OpenAI response if present.")
    pattern = r'^```(?:json)?\s*\n(.*?)\n```$'
    match = re.match(pattern, text, re.DOTALL)
    if match:
        logger.debug("Code fences detected and removed from the response.")
        return match.group(1)
    logger.debug("No code fences found in the response.")
    return text

def fetch_updated_config(target_url):
    """
    [✓] Fetches an updated Burp Suite Pro scan config from OpenAI's model.
    """
    OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
    if not OPENAI_API_KEY:
        logger.error("OPENAI_API_KEY is not set. Please set it as an environment variable.")
        raise EnvironmentError("OPENAI_API_KEY is not set. Please set it as an environment variable.")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}"
    }

    json_config = '''{
        "crawler":{
            "crawl_limits":{
                "maximum_crawl_time":3,
                "maximum_request_count":0,
                "maximum_unique_locations":1500
            },
            "crawl_optimization":{
                "await_navigation_timeout":10,
                "clickable_fingerprinting_threshold":1,
                "crawl_strategy":"fastest",
                "crawl_strategy_customized":false,
                "crawl_using_provided_logins_only":true,
                "dom_idle_threshold":0,
                "drop_advert_requests":true,
                "form_destination_optimization_threshold":1,
                "form_submission_optimization_threshold":1,
                "fully_explore_floating_forms":false,
                "incy_wincy":true,
                "link_fingerprinting_threshold":1,
                "logging_directory":"",
                "logging_enabled":false,
                "loopback_link_fingerprinting_threshold":1,
                "maximum_form_field_permutations":4,
                "maximum_form_permutations":5,
                "maximum_link_depth":4,
                "maximum_unmatched_anchor_tolerance":3,
                "maximum_unmatched_form_tolerance":0,
                "maximum_unmatched_frame_tolerance":0,
                "maximum_unmatched_iframe_tolerance":3,
                "maximum_unmatched_image_area_tolerance":0,
                "maximum_unmatched_redirect_tolerance":0,
                "network_idle_threshold":0,
                "total_unmatched_feature_tolerance":3,
                "use_accessible_text_for_visible_text":true,
                "use_browser_cache":true
            },
            "crawl_project_option_overrides":{
                "connect_timeout":10,
                "normal_timeout":10
            },
            "customization":{
                "allow_all_clickables":true,
                "allow_out_of_scope_resources":true,
                "application_uses_fragments_for_routing":"unsure",
                "browser_based_navigation_mode":"only_if_hardware_supports",
                "customize_user_agent":false,
                "guess_hidden_graphql_endpoints":false,
                "maximum_items_from_sitemap":1000,
                "maximum_speculative_links":1000,
                "parse_api_definitions":true,
                "parse_soap_wsdls":true,
                "perform_graphql_introspection":true,
                "request_robots_txt":true,
                "request_sitemap":true,
                "request_speculative":true,
                "submit_forms":true,
                "timeout_for_in_progress_resource_requests":10,
                "user_agent":""
            },
            "error_handling":{
                "number_of_follow_up_passes":1,
                "pause_task_requests_timed_out_count":0,
                "pause_task_requests_timed_out_percentage":0
            }
        },
        "scanner": {
            "audit_optimization": {
                "consolidate_passive_issues": true,
                "follow_redirections": true,
                "maintain_session": true,
                "max_items_in_progress": 10,
                "maximum_crawl_and_audit_time": 0,
                "scan_accuracy": "normal",
                "scan_speed": "thorough",
                "skip_ineffective_checks": true
            },
            "issues_reported": {
                "scan_type_intrusive_active": true,
                "scan_type_javascript_analysis": true,
                "scan_type_light_active": true,
                "scan_type_medium_active": true,
                "scan_type_passive": true,
                "select_individual_issues": true,
                "selected_issues": [
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x01000100"
                    },
                    {
                        "detection_methods": [
                            {
                                "enabled": true,
                                "name": "Error messages"
                            },
                            {
                                "enabled": true,
                                "name": "Time delays"
                            },
                            {
                                "enabled": true,
                                "name": "Boolean conditions"
                            },
                            {
                                "enabled": true,
                                "name": "Oracle specific"
                            },
                            {
                                "enabled": true,
                                "name": "MySQL specific"
                            },
                            {
                                "enabled": true,
                                "name": "SQL Server specific"
                            },
                            {
                                "enabled": true,
                                "name": "Burp Collaborator"
                            },
                            {
                                "enabled": true,
                                "name": "PostgreSQL specific"
                            }
                        ],
                        "enabled": true,
                        "type_index": "0x00100210"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x00100f10"
                    },
                    {
                        "detection_methods": [
                            {
                                "enabled": true,
                                "name": "Javascript static analysis"
                            },
                            {
                                "enabled": true,
                                "name": "Javascript dynamic analysis"
                            }
                        ],
                        "enabled": false,
                        "type_index": "0x00200320"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x01000200"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x01000300"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x01000400"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x01000500"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x08000000"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x09000000"
                    },
                    {
                        "detection_methods": [
                            {
                                "enabled": true,
                                "name": "Javascript static analysis"
                            },
                            {
                                "enabled": true,
                                "name": "Javascript dynamic analysis"
                            }
                        ],
                        "enabled": false,
                        "type_index": "0x00200321"
                    },
                    {
                        "detection_methods": [
                            {
                                "enabled": true,
                                "name": "Javascript static analysis"
                            },
                            {
                                "enabled": true,
                                "name": "Javascript dynamic analysis"
                            }
                        ],
                        "enabled": false,
                        "type_index": "0x00200322"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x00200328"
                    },
                    {
                        "detection_methods": [
                            {
                                "enabled": true,
                                "name": "Error messages"
                            },
                            {
                                "enabled": true,
                                "name": "Burp Collaborator"
                            },
                            {
                                "enabled": true,
                                "name": "Burp Infiltrator"
                            }
                        ],
                        "enabled": false,
                        "type_index": "0x00100700"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x00100900"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x00100a00"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x00100b00"
                    },
                    {
                        "detection_methods": [
                            {
                                "enabled": true,
                                "name": "String echo"
                            },
                            {
                                "enabled": true,
                                "name": "Time delays"
                            },
                            {
                                "enabled": true,
                                "name": "Burp Collaborator"
                            }
                        ],
                        "enabled": false,
                        "type_index": "0x00100c00"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x00100d00"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x00100e00"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x00100f00"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x00101000"
                    },
                    {
                        "detection_methods": [
                            {
                                "enabled": true,
                                "name": "Burp Collaborator"
                            },
                            {
                                "enabled": true,
                                "name": "String echo"
                            }
                        ],
                        "enabled": false,
                        "type_index": "0x00101080"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x00200180"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x006000d8"
                    },
                    {
                        "detection_methods": [],
                        "enabled": true,
                        "type_index": "0x00400480"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x00500080"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x00500980"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x006000b0"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x005009b0"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x00600080"
                    },
                    {
                        "detection_methods": [],
                        "enabled": false,
                        "type_index": "0x005009a0"
                    }
                ],
                "store_issues_within_queue_items": false
            }
        }
    }'''

    # Get the actual current date/time in ISO 8601 format
    current_datetime = datetime.datetime.now().isoformat()

    prompt = f"""
Configure this existing Burp Suite Professional's REST API custom JSON configuration file to scan for OWASP Top 10 vulnerabilities. Make sure there are no errors within your response.

Use the actual current date/time (ISO 8601 format): {current_datetime}

JSON Config:
{json_config}

Here are the vulnerability references:

Name
Severity
Index (hex)
Index (dec)
Classifications
OS command injection

High

0x00100100

1048832

CWE-77
CWE-78
CWE-116
SQL injection

High

0x00100200

1049088

CWE-89
CWE-94
CWE-116
SQL injection (second order)

High

0x00100210

1049104

CWE-89
CWE-94
CWE-116
ASP.NET tracing enabled

High

0x00100280

1049216

CWE-10
CWE-11
File path traversal

High

0x00100300

1049344

CWE-22
CWE-23
CWE-35
CWE-36
XML external entity injection

High

0x00100400

1049600

CWE-611
LDAP injection

High

0x00100500

1049856

CWE-90
CWE-116
XPath injection

High

0x00100600

1050112

CWE-94
CWE-116
CWE-159
CWE-643
XML injection

Medium

0x00100700

1050368

CWE-91
CWE-116
CWE-159
CWE-611
CWE-776
ASP.NET debugging enabled

Medium

0x00100800

1050624

CWE-11
Broken access control

Information

0x00100850

1050704

CWE-284
HTTP PUT method is enabled

High

0x00100900

1050880

CWE-650
Out-of-band resource load (HTTP)

High

0x00100a00

1051136

CWE-610
CWE-918
File path manipulation

High

0x00100b00

1051392

CWE-22
CWE-23
CWE-35
CWE-36
PHP code injection

High

0x00100c00

1051648

CWE-94
CWE-116
CWE-159
Server-side JavaScript code injection

High

0x00100d00

1051904

CWE-94
CWE-95
CWE-116
Perl code injection

High

0x00100e00

1052160

CWE-94
CWE-95
CWE-116
Ruby code injection

High

0x00100f00

1052416

CWE-94
CWE-95
CWE-116
Expression Language injection

High

0x00100f10

1052432

CWE-94
CWE-95
CWE-116
Unidentified code injection

High

0x00101000

1052672

CWE-94
CWE-95
CWE-116
Server-side template injection

High

0x00101080

1052800

CWE-94
CWE-95
CWE-116
SSI injection

High

0x00101100

1052928

CWE-96
CWE-116
CWE-159
Cross-site scripting (stored)

High

0x00200100

2097408

CWE-79
CWE-80
CWE-116
CWE-159
HTTP request smuggling

High

0x00200140

2097472

CWE-444
Client-side desync

High

0x00200141

2097473

CWE-444
Web cache poisoning

High

0x00200180

2097536

CWE-436
HTTP response header injection

High

0x00200200

2097664

CWE-113
Cross-site scripting (reflected)

High

0x00200300

2097920

CWE-79
CWE-80
CWE-116
CWE-159
Client-side template injection

High

0x00200308

2097928

CWE-116
CWE-159
Cross-site scripting (DOM-based)

High

0x00200310

2097936

CWE-79
CWE-80
CWE-116
CWE-159
Cross-site scripting (reflected DOM-based)

High

0x00200311

2097937

CWE-79
CWE-80
CWE-116
CWE-159
Cross-site scripting (stored DOM-based)

High

0x00200312

2097938

CWE-79
CWE-80
CWE-116
CWE-159
Client-side prototype pollution

Information

0x00200316

2097942

CWE-1321
JavaScript injection (DOM-based)

High

0x00200320

2097952

CWE-94
CWE-95
CWE-116
JavaScript injection (reflected DOM-based)

High

0x00200321

2097953

CWE-94
CWE-95
CWE-116
JavaScript injection (stored DOM-based)

High

0x00200322

2097954

CWE-94
CWE-95
CWE-116
Path-relative style sheet import

Information

0x00200328

2097960

CWE-16
Client-side SQL injection (DOM-based)

High

0x00200330

2097968

CWE-89
CWE-116
CWE-159
Client-side SQL injection (reflected DOM-based)

High

0x00200331

2097969

CWE-89
CWE-116
CWE-159
Client-side SQL injection (stored DOM-based)

High

0x00200332

2097970

CWE-89
CWE-116
CWE-159
WebSocket URL poisoning (DOM-based)

High

0x00200340

2097984

CWE-345
CWE-346
CWE-441
WebSocket URL poisoning (reflected DOM-based)

High

0x00200341

2097985

CWE-345
CWE-346
CWE-441
WebSocket URL poisoning (stored DOM-based)

High

0x00200342

2097986

CWE-345
CWE-346
CWE-441
Local file path manipulation (DOM-based)

High

0x00200350

2098000

CWE-22
CWE-73
Local file path manipulation (reflected DOM-based)

High

0x00200351

2098001

CWE-22
CWE-73
Local file path manipulation (stored DOM-based)

High

0x00200352

2098002

CWE-22
CWE-73
Client-side XPath injection (DOM-based)

Low

0x00200360

2098016

CWE-79
CWE-116
CWE-159
Client-side XPath injection (reflected DOM-based)

Low

0x00200361

2098017

CWE-79
CWE-116
CWE-159
Client-side XPath injection (stored DOM-based)

Low

0x00200362

2098018

CWE-79
CWE-116
CWE-159
Client-side JSON injection (DOM-based)

Low

0x00200370

2098032

CWE-79
CWE-116
CWE-159
Client-side JSON injection (reflected DOM-based)

Low

0x00200371

2098033

CWE-79
CWE-116
CWE-159
Client-side JSON injection (stored DOM-based)

Low

0x00200372

2098034

CWE-79
CWE-116
CWE-159
Flash cross-domain policy

High

0x00200400

2098176

CWE-942
Silverlight cross-domain policy

High

0x00200500

2098432

CWE-942
Content security policy: allowlisted script resources

Information

0x00200503

2098435

CWE-79
CWE-80
CWE-116
CWE-159
Content security policy: allows untrusted script execution

Information

0x00200504

2098436

CWE-79
CWE-80
CWE-116
CWE-159
Content security policy: allows untrusted style execution

Information

0x00200505

2098437

CWE-116
CWE-159
Content security policy: malformed syntax

Information

0x00200506

2098438

Content security policy: allows clickjacking

Information

0x00200507

2098439

CWE-693
CWE-1021
Content security policy: allows form hijacking

Information

0x00200508

2098440

CWE-116
Content security policy: not enforced

Information

0x00200509

2098441

GraphQL endpoint found

Information

0x00200510

2098448

GraphQL endpoint discovered

Information

0x00200511

2098449

GraphQL introspection enabled

Low

0x00200512

2098450

CWE-200
GraphQL suggestions enabled

Low

0x00200513

2098451

CWE-200
GraphQL content type not validated

Low

0x00200514

2098452

CWE-352
Cross-origin resource sharing

Information

0x00200600

2098688

CWE-942
Cross-origin resource sharing: arbitrary origin trusted

High

0x00200601

2098689

CWE-942
Cross-origin resource sharing: unencrypted origin trusted

Low

0x00200602

2098690

CWE-942
Cross-origin resource sharing: all subdomains trusted

Low

0x00200603

2098691

CWE-942
Web cache deception

Medium

0x00200650

2098768

Cross-site request forgery

Medium

0x00200700

2098944

CWE-352
SMTP header injection

Medium

0x00200800

2099200

CWE-93
CWE-159
JWT signature not verified

High

0x00200900

2099456

CWE-345
CWE-347
JWT none algorithm supported

High

0x00200901

2099457

CWE-345
JWT self-signed JWK header supported

High

0x00200902

2099458

JWT weak HMAC secret

High

0x00200903

2099459

JWT arbitrary jku header supported

High

0x00200904

2099460

JWT arbitrary x5u header supported

High

0x00200905

2099461

Cleartext submission of password

High

0x00300100

3145984

CWE-319
External service interaction (DNS)

Information

0x00300200

3146240

CWE-918
CWE-406
External service interaction (HTTP)

High

0x00300210

3146256

CWE-918
CWE-406
External service interaction (SMTP)

Information

0x00300220

3146272

CWE-16
CWE-406
Referer-dependent response

Information

0x00400100

4194560

CWE-16
CWE-213
Spoofable client IP address

Information

0x00400110

4194576

CWE-16
User agent-dependent response

Information

0x00400120

4194592

CWE-16
Password returned in later response

Medium

0x00400200

4194816

CWE-204
Password submitted using GET method

Low

0x00400300

4195072

CWE-598
Password returned in URL query string

Low

0x00400400

4195328

CWE-598
SQL statement in request parameter

Medium

0x00400480

4195456

CWE-598
Cross-domain POST

Information

0x00400500

4195584

CWE-16
ASP.NET ViewState without MAC enabled

High

0x00400600

4195840

CWE-642
XML entity expansion

Medium

0x00400700

4196096

CWE-776
Long redirection response

Information

0x00400800

4196352

CWE-698
Serialized object in HTTP message

High

0x00400900

4196608

CWE-502
Duplicate cookies set

Information

0x00400a00

4196864

CWE-16
Input returned in response (stored)

Information

0x00400b00

4197120

CWE-20
CWE-116
Input returned in response (reflected)

Information

0x00400c00

4197376

CWE-20
CWE-116
Suspicious input transformation (reflected)

Information

0x00400d00

4197632

CWE-20
Suspicious input transformation (stored)

Information

0x00400e00

4197888

CWE-20
Request URL override

Information

0x00400f00

4198144

CWE-436
Vulnerable JavaScript dependency

Low

0x00500080

5243008

CWE-1104
Open redirection (reflected)

Low

0x00500100

5243136

CWE-601
Open redirection (stored)

Medium

0x00500101

5243137

CWE-601
Open redirection (DOM-based)

Low

0x00500110

5243152

CWE-601
Open redirection (reflected DOM-based)

Low

0x00500111

5243153

CWE-601
Open redirection (stored DOM-based)

Medium

0x00500112

5243154

CWE-601
TLS cookie without secure flag set

Medium

0x00500200

5243392

CWE-614
Cookie scoped to parent domain

Low

0x00500300

5243648

CWE-16
Cross-domain Referer leakage

Information

0x00500400

5243904

CWE-200
Cross-domain script include

Information

0x00500500

5244160

CWE-829
Cookie without HttpOnly flag set

Low

0x00500600

5244416

CWE-16
Session token in URL

Medium

0x00500700

5244672

CWE-200
CWE-384
CWE-598
Password field with autocomplete enabled

Low

0x00500800

5244928

CWE-200
Password value set in cookie

Medium

0x00500900

5245184

CWE-287
File upload functionality

Information

0x00500980

5245312

CWE-434
Frameable response (potential Clickjacking)

Information

0x005009a0

5245344

CWE-693
CWE-1021
Browser cross-site scripting filter disabled

Information

0x005009b0

5245360

CWE-16
HTTP TRACE method is enabled

Information

0x00500a00

5245440

CWE-16
Cookie manipulation (DOM-based)

Low

0x00500b00

5245696

CWE-565
CWE-829
Cookie manipulation (reflected DOM-based)

Low

0x00500b01

5245697

CWE-565
CWE-829
Cookie manipulation (stored DOM-based)

Low

0x00500b02

5245698

CWE-565
CWE-829
Ajax request header manipulation (DOM-based)

Low

0x00500c00

5245952

CWE-116
Ajax request header manipulation (reflected DOM-based)

Low

0x00500c01

5245953

CWE-116
Ajax request header manipulation (stored DOM-based)

Low

0x00500c02

5245954

CWE-116
Denial of service (DOM-based)

Information

0x00500d00

5246208

CWE-400
Denial of service (reflected DOM-based)

Information

0x00500d01

5246209

CWE-400
Denial of service (stored DOM-based)

Low

0x00500d02

5246210

CWE-400
HTML5 web message manipulation (DOM-based)

Information

0x00500e00

5246464

CWE-20
HTML5 web message manipulation (reflected DOM-based)

Information

0x00500e01

5246465

CWE-20
HTML5 web message manipulation (stored DOM-based)

Information

0x00500e02

5246466

CWE-20
HTML5 storage manipulation (DOM-based)

Information

0x00500f00

5246720

CWE-20
HTML5 storage manipulation (reflected DOM-based)

Information

0x00500f01

5246721

CWE-20
HTML5 storage manipulation (stored DOM-based)

Information

0x00500f02

5246722

CWE-20
Link manipulation (DOM-based)

Low

0x00501000

5246976

CWE-20
Link manipulation (reflected DOM-based)

Low

0x00501001

5246977

CWE-20
Link manipulation (stored DOM-based)

Low

0x00501002

5246978

CWE-20
Link manipulation (reflected)

Information

0x00501003

5246979

CWE-73
CWE-20
Link manipulation (stored)

Information

0x00501004

5246980

CWE-73
CWE-20
Document domain manipulation (DOM-based)

Medium

0x00501100

5247232

CWE-20
Document domain manipulation (reflected DOM-based)

Medium

0x00501101

5247233

CWE-20
Document domain manipulation (stored DOM-based)

Medium

0x00501102

5247234

CWE-20
DOM data manipulation (DOM-based)

Information

0x00501200

5247488

CWE-20
DOM data manipulation (reflected DOM-based)

Information

0x00501201

5247489

CWE-20
DOM data manipulation (stored DOM-based)

Information

0x00501202

5247490

CWE-20
CSS injection (reflected)

Medium
---
ONLY RESPOND IN JSON. RETURN THE ENTIRE JSON CONFIGURATION.
"""

    logger.info("Preparing to send request to OpenAI API for updated configuration.")

    data = {
        "model": "o3-mini",
        "messages": [
            {"role": "user", "content": prompt}
        ],
    }

    logger.debug(f"OpenAI API Request Payload: {json.dumps(data, indent=4)}")

    try:
        response = requests.post("https://api.openai.com/v1/chat/completions", headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        }, json=data)
        logger.info(f"Sent request to OpenAI API. Status Code: {response.status_code}")
        logger.debug(f"OpenAI API Response Headers: {response.headers}")
        logger.debug(f"OpenAI API Response Body: {response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Request to OpenAI API failed: {e}")
        raise

    if response.ok:
        try:
            response_json = response.json()
            logger.debug(f"OpenAI API JSON Response: {json.dumps(response_json, indent=4)}")
            content = response_json['choices'][0]['message']['content']
            content = strip_code_fences(content)
            return content
        except (KeyError, ValueError) as e:
            logger.error(f"Error parsing OpenAI API response as JSON: {e}")
            logger.error(f"Raw OpenAI API Response: {response.text}")
            raise RuntimeError("Invalid response from OpenAI API") from e
    else:
        logger.error(f"Failed to fetch updated config from OpenAI API. Status code: {response.status_code}")
        logger.error(f"Response Text: {response.text}")
        raise RuntimeError(f"Failed to fetch updated config: {response.status_code} - {response.text}")

def update_config_file(config_path, target_url):
    """
    [✓] Updates the Burp Suite Pro configuration JSON file using OpenAI's model.
    """
    logger.info("Starting to update configuration file.")
    try:
        updated_config = fetch_updated_config(target_url)
        logger.info("Successfully fetched updated configuration from OpenAI.")
    except Exception as e:
        logger.error(f"Failed to fetch updated configuration: {e}")
        raise

    try:
        parsed_config = json.loads(updated_config)
        logger.debug(f"Parsed JSON Configuration: {json.dumps(parsed_config, indent=4)}")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON from OpenAI response: {e}")
        logger.error(f"OpenAI Response Content: {updated_config}")
        raise ValueError("o3-mini response is not valid JSON") from e

    try:
        with open(config_path, "w") as f:
            json.dump(parsed_config, f, indent=4)
        logger.info(f"Updated configuration saved to {config_path}")
    except IOError as e:
        logger.error(f"Failed to write updated configuration to file: {e}")
        raise

def launch_scan():
    """
    [✓] Launches the Burp Suite scan using the updated configuration.
    """
    API_URL = "http://127.0.0.1:1337/v0.1/scan"
    BURP_API_TOKEN = "burp-key"  # Fetch from environment variable in production
    POLL_INTERVAL = 10  # seconds
    OPENAI_MODEL = "o3-mini"

    if not BURP_API_TOKEN:
        logger.error("BURP_API_TOKEN is not set. Please set it as an environment variable.")
        raise EnvironmentError("BURP_API_TOKEN is not set. Please set it as an environment variable.")

    config_path = "OWASP.json"  # Adjust path as necessary
    target_url = input("Enter the target URL (e.g., http://10.10.63.241): ").strip()

    if not target_url:
        logger.error("Target URL cannot be empty.")
        raise ValueError("Target URL cannot be empty.")

    logger.info(f"Target URL entered: {target_url}")

    try:
        update_config_file(config_path, target_url)
    except Exception as e:
        logger.error(f"Failed to update configuration file: {e}")
        raise

    if not os.path.isfile(config_path):
        logger.error(f"Could not find configuration file at {config_path}")
        raise FileNotFoundError(f"Could not find {config_path}")

    try:
        with open(config_path, "r") as f:
            custom_config = json.load(f)
        logger.debug(f"Loaded custom configuration from {config_path}")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse configuration file as JSON: {e}")
        raise
    except IOError as e:
        logger.error(f"Failed to read configuration file: {e}")
        raise

    payload = {
        "urls": [target_url],
        "name": None,
        "scope": {
            "include_paths": [target_url],
            "exclude_paths": []
        },
        "scan_configurations": [
            {
                "type": "CustomConfiguration",
                "config": json.dumps(custom_config)
            }
        ]
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {BURP_API_TOKEN}"
    }

    logger.info("Sending scan request to Burp Suite API.")
    logger.debug(f"Burp Suite API Request Payload: {json.dumps(payload, indent=4)}")

    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        logger.info(f"Sent scan request to Burp Suite API. Status Code: {response.status_code}")
        logger.debug(f"Burp Suite API Response Headers: {response.headers}")
        logger.debug(f"Burp Suite API Response Body: {response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Request to Burp Suite API failed: {e}")
        raise

    if response.ok:
        logger.info("Scan created/launched successfully!")
        content_type = response.headers.get('Content-Type', '')
        if 'application/json' in content_type.lower():
            try:
                resp_json = response.json()
                logger.debug(f"Burp Suite API JSON Response: {json.dumps(resp_json, indent=4)}")
                print("Response JSON:", json.dumps(resp_json, indent=4))
                task_id = resp_json.get("id")
                if task_id:
                    logger.info(f"Monitoring scan progress for Task ID: {task_id}")
                    monitor_scan(task_id, API_URL, BURP_API_TOKEN, POLL_INTERVAL, OPENAI_MODEL)
                else:
                    logger.error("Task ID not found in the response.")
            except ValueError:
                logger.warning("Burp Suite API response is not valid JSON.")
                print("Response (not valid JSON):", response.text)
                location = response.headers.get("Location")
                if location:
                    task_id = location.rstrip('/').split('/')[-1]
                    logger.info(f"Extracted Task ID from Location header: {task_id}")
                    monitor_scan(task_id, API_URL, BURP_API_TOKEN, POLL_INTERVAL, OPENAI_MODEL)
                else:
                    logger.error("Location header not found. Cannot extract Task ID.")
        elif response.status_code == 201:
            location = response.headers.get("Location")
            if location:
                task_id = location.rstrip('/').split('/')[-1]
                logger.info(f"Extracted Task ID from Location header: {task_id}")
                monitor_scan(task_id, API_URL, BURP_API_TOKEN, POLL_INTERVAL, OPENAI_MODEL)
            else:
                logger.error("Location header not found. Cannot extract Task ID.")
                print("Response (non-JSON):", response.text)
        else:
            logger.warning("Burp Suite API response is not JSON.")
            print("Response (non-JSON):", response.text)
    else:
        logger.error(f"Failed to create/launch scan. Status code: {response.status_code}")
        logger.error(f"Burp Suite API Response Text: {response.text}")
        print(f"Failed to create/launch scan. Status code: {response.status_code}")
        print("Response text:", response.text)

def monitor_scan(task_id, api_url, api_token, poll_interval, openai_model):
    """
    [✓] Monitors the scan progress and processes vulnerabilities when complete.
    """
    scan_url = f"{api_url}/{task_id}"
    headers = {
        "Authorization": f"Bearer {api_token}"
    }

    while True:
        response = requests.get(scan_url, headers=headers)
        if not response.ok:
            logger.error(f"Failed to fetch scan status. Status code: {response.status_code}")
            logger.error(f"Response text: {response.text}")
            return

        try:
            data = response.json()
        except json.JSONDecodeError:
            logger.error("Failed to parse scan status response JSON.")
            logger.error(f"Response text: {response.text}")
            return

        scan_status = data.get("scan_status", "").lower()
        issues = data.get("issue_events", [])

        logger.info(f"Scan Status: {scan_status}")

        if issues:
            logger.info("New Issues Found:")
            for issue_event in issues:
                issue = issue_event.get("issue", {})
                print(json.dumps(issue, indent=4))

        if scan_status in ["succeeded", "failed", "paused"]:
            logger.info(f"Scan finished with status: {scan_status}")
            if scan_status in ["succeeded", "paused"]:
                logger.info("Final list of issues:")
                for issue_event in issues:
                    issue = issue_event.get("issue", {})
                    print(json.dumps(issue, indent=4))
                process_exploitable_vulnerabilities(issues, openai_model)
            break

        time.sleep(poll_interval)

def process_exploitable_vulnerabilities(issues, openai_model):
    """
    [✓] Processes scan issues, ensuring each vulnerability is unique, generates and executes pentest scripts.
    """
    exploitable_vulns = {
        # Code Injection vulnerabilities (example mapping)
        1048832: ("Code Injection", "OS command injection"),
        1049088: ("Code Injection", "SQL injection"),
        1049104: ("Code Injection", "SQL injection (second order)"),
        1049856: ("Code Injection", "LDAP injection"),
        1050112: ("Code Injection", "XPath injection"),
        1051648: ("Code Injection", "PHP code injection"),
        1051904: ("Code Injection", "Server-side JavaScript code injection"),
        1052160: ("Code Injection", "Perl code injection"),
        1052416: ("Code Injection", "Ruby code injection"),
        1052432: ("Code Injection", "Python code injection"),
        1052448: ("Code Injection", "Expression Language injection"),
        1052672: ("Code Injection", "Unidentified code injection"),
        1052800: ("Code Injection", "Server-side template injection"),
        1052928: ("Code Injection", "SSI injection"),
        2097952: ("Code Injection", "JavaScript injection (DOM-based)"),
        2097953: ("Code Injection", "JavaScript injection (reflected DOM-based)"),
        2097954: ("Code Injection", "JavaScript injection (stored DOM-based)"),
        2097968: ("Code Injection", "Client-side SQL injection (DOM-based)"),
        2097969: ("Code Injection", "Client-side SQL injection (reflected DOM-based)"),
        2097970: ("Code Injection", "Client-side SQL injection (stored DOM-based)"),

        # Cross-site Scripting (XSS)
        2097408: ("Cross-site Scripting (XSS)", "Cross-site scripting (stored)"),
        2097920: ("Cross-site Scripting (XSS)", "Cross-site scripting (reflected)"),
        2097936: ("Cross-site Scripting (XSS)", "Cross-site scripting (DOM-based)"),
        2097937: ("Cross-site Scripting (XSS)", "Cross-site scripting (reflected DOM-based)"),
        2097938: ("Cross-site Scripting (XSS)", "Cross-site scripting (stored DOM-based)"),

        # Path and File Manipulation
        1049344: ("Path and File Manipulation", "File path traversal"),
        1051392: ("Path and File Manipulation", "File path manipulation"),
        2098000: ("Path and File Manipulation", "Local file path manipulation (DOM-based)"),
        2098001: ("Path and File Manipulation", "Local file path manipulation (reflected DOM-based)"),
        2098002: ("Path and File Manipulation", "Local file path manipulation (stored DOM-based)"),

        # WebSocket Exploits
        2097984: ("WebSocket Exploits", "WebSocket URL poisoning (DOM-based)"),
        2097985: ("WebSocket Exploits", "WebSocket URL poisoning (reflected DOM-based)"),
        2097986: ("WebSocket Exploits", "WebSocket URL poisoning (stored DOM-based)"),

        # Misconfigurations and Information Leakage
        1050880: ("Misconfigurations and Information Leakage", "HTTP PUT method is enabled"),
        2098688: ("Misconfigurations and Information Leakage", "Cross-origin resource sharing"),
        2098689: ("Misconfigurations and Information Leakage", "Cross-origin resource sharing: arbitrary origin trusted"),
        2099456: ("Misconfigurations and Information Leakage", "JWT signature not verified"),
        2099457: ("Misconfigurations and Information Leakage", "JWT none algorithm supported"),
        2099458: ("Misconfigurations and Information Leakage", "JWT self-signed JWK header supported"),
        2099459: ("Misconfigurations and Information Leakage", "JWT weak HMAC secret"),
        2099460: ("Misconfigurations and Information Leakage", "JWT arbitrary jku header supported"),
        2099461: ("Misconfigurations and Information Leakage", "JWT arbitrary x5u header supported"),
        3145984: ("Misconfigurations and Information Leakage", "Cleartext submission of password"),

        # Authentication/Session Exploits
        4194816: ("Authentication/Session Exploits", "Password returned in later response"),
        5244672: ("Authentication/Session Exploits", "Session token in URL"),
        5244928: ("Authentication/Session Exploits", "Password field with autocomplete enabled"),
        5245184: ("Authentication/Session Exploits", "Password value set in cookie"),

        # HTTP Parameter and Header Manipulation
        5245952: ("HTTP Parameter and Header Manipulation", "Ajax request header manipulation (DOM-based)"),
        5245953: ("HTTP Parameter and Header Manipulation", "Ajax request header manipulation (reflected DOM-based)"),
        5245954: ("HTTP Parameter and Header Manipulation", "Ajax request header manipulation (stored DOM-based)"),
        2097664: ("HTTP Parameter and Header Manipulation", "HTTP response header injection"),
    }

    matched_vulns = {}

    for issue_event in issues:
        issue = issue_event.get("issue", {})
        type_index = issue.get("type_index")
        if type_index is None:
            continue

        if isinstance(type_index, str):
            try:
                type_index = int(type_index, 16)
            except ValueError:
                logger.warning(f"Invalid type_index format: {type_index}")
                continue

        if type_index in exploitable_vulns:
            category, vuln_name = exploitable_vulns[type_index]
            unique_key = f"{vuln_name}_{json.dumps(issue, sort_keys=True)}"
            if unique_key not in matched_vulns:
                vuln_info = {
                    "category": category,
                    "vuln_name": vuln_name,
                    "issue_data": issue,
                }
                matched_vulns[unique_key] = vuln_info
                vulnerability_context_buffer.append(vuln_info)

    if matched_vulns:
        logger.info("### Unique Exploitable Vulnerabilities Found:")
        for unique_key, vuln in matched_vulns.items():
            logger.info(f"\n#### {vuln['category']}")
            logger.info(f"- {vuln['vuln_name']}")

        for unique_key, vuln in matched_vulns.items():
            vuln_name = vuln['vuln_name']
            issue_data = vuln['issue_data']
            logger.info(f"\nProcessing vulnerability: {vuln_name}")
            try:
                pentest_script = generate_pentest_script(vuln_name, issue_data, openai_model)
                if pentest_script:
                    execution_result = execute_pentest_script(pentest_script)
                    pentest_script_context_buffer.append({
                        "vulnerability": vuln_name,
                        "pentest_script": pentest_script,
                        "execution_result": execution_result
                    })
            except Exception as e:
                logger.error(f"Error processing vulnerability '{vuln_name}': {e}")
    else:
        logger.info("No unique exploitable vulnerabilities were found.")

def generate_pentest_script(vuln_name, issue_data, model):
    """
    [✓] Sends vulnerability data to OpenAI to generate a pentesting Python script.
    """
    prompt = (
        f"You are a professional penetration tester. Generate a Python script that can confirm the exploitability of the following vulnerability "
        f"in an OWASP Juice Shop simulated environment.\n\n"
        f"Vulnerability Name: {vuln_name}\n"
        f"Vulnerability Data: {json.dumps(issue_data, indent=4)}\n\n"
        f"Provide only the Python script without any additional text or explanations."
    )

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "assistant", "content": "You generate Python scripts for penetration testing."},
                {"role": "user", "content": prompt}
            ]
        )
        pentest_script = response.choices[0].message.content.strip()

        pentest_script = re.sub(r'^```python\s*', '', pentest_script, flags=re.MULTILINE)
        pentest_script = re.sub(r'\s*```$', '', pentest_script, flags=re.MULTILINE)

        logger.info(f"Pentesting script generated for vulnerability '{vuln_name}'.")
        return pentest_script
    except Exception as e:
        logger.error(f"Failed to generate pentest script for vulnerability '{vuln_name}': {e}")
        return None

def execute_pentest_script(script):
    """
    [✓] Executes the generated pentest Python script.
    """
    tmp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp_file:
            tmp_file.write(script)
            tmp_file_path = tmp_file.name

        logger.info(f"Executing pentest script: {tmp_file_path}")
        result = subprocess.run(
            ["python3", tmp_file_path],
            capture_output=True,
            text=True,
            timeout=60
        )

        logger.info("Pentest Script Output:")
        logger.info(result.stdout)
        if result.stderr:
            logger.warning("Pentest Script Errors:")
            logger.warning(result.stderr)
        execution_details = {
            "stdout": result.stdout,
            "stderr": result.stderr
        }
        return execution_details
    except subprocess.TimeoutExpired:
        logger.error("Pentest script execution timed out.")
        return {"stdout": "", "stderr": "Execution timed out."}
    except Exception as e:
        logger.error(f"Failed to execute pentest script: {e}")
        return {"stdout": "", "stderr": str(e)}
    finally:
        if tmp_file_path and os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)
            logger.info(f"Deleted temporary pentest script file: {tmp_file_path}")

def print_context_buffers():
    """
    [✓] Prints the global context buffers for vulnerabilities and pentest scripts.
    """
    print("\n=== Vulnerability Context Buffer ===")
    print(json.dumps(vulnerability_context_buffer, indent=4))
    print("\n=== Pentest Script Context Buffer ===")
    print(json.dumps(pentest_script_context_buffer, indent=4))

def generate_executive_summary(model):
    """
    [STEP 1] Build a prompt that instructs the model to output a valid JSON object.
        - We specify each key and its expected type for each table.
        - Note: compliance_date is set to null for testing.
        - The global context buffers are included so the model can analyze them.
    [STEP 2] Call the OpenAI API using JSON mode.
    [STEP 3] Validate the output by attempting to parse it as JSON.
    [STEP 4] Return the structured JSON data or an error dictionary if something goes awry.
    """
    # Get the current date/time in ISO 8601 format
    current_datetime = datetime.datetime.now().isoformat()

    # Dump the context buffers as JSON strings
    vulnerability_context = json.dumps(vulnerability_context_buffer, indent=4)
    pentest_context = json.dumps(pentest_script_context_buffer, indent=4)
    
    prompt = (
        "You are a professional penetration tester and database integrator. Generate a structured JSON output for database insertion. "
        "Using the following context buffers, analyze the discovered vulnerabilities and executed pentest scripts to produce data for the database.\n\n"
        "For any date or timestamp fields, use the current date and time: " + current_datetime + ".\n\n"
        "vulnerability_context_buffer:\n" + vulnerability_context + "\n\n"
        "pentest_script_context_buffer:\n" + pentest_context + "\n\n"
        "The JSON must contain the following keys exactly, with arrays of objects as values:\n\n"
        "\"reports\": an array of objects, each with the following keys: "
        "report_id (integer), test_id (integer), vulnerability_count (integer), compliance_score (numeric), "
        "framework_name (string), compliance_date (null for testing), risk_score (numeric), summary (string), "
        "detailed_findings (string), report_date (string timestamp).\n\n"
        "\"suggestions\": an array of objects, each with: suggestion_id (integer), vulnerability_id (integer), "
        "suggestion_text (string), roi (numeric).\n\n"
        "\"target_details\": an array of objects, each with: target_id (integer), test_id (integer), url_target (string).\n\n"
        "\"test_configurations\": an array of objects, each with: config_id (integer), test_id (integer), "
        "config_name (string), config_date (string or null), status (string), options (object).\n\n"
        "\"tests\": an array of objects, each with: test_id (integer), user_id (integer), test_name (string), "
        "test_date (string, date), test_status (string).\n\n"
        "\"vulnerabilities\": an array of objects, each with: vulnerability_id (integer), test_id (integer), "
        "vulnerability_name (string), endpoint (string), severity (string), cvss_score (numeric), potential_loss (numeric).\n\n"
        "Output only valid JSON with no additional commentary or whitespace. "
        "If you cannot generate the JSON, output an error message in JSON format."
    )

    try:
        # [CHECKLIST] API call using JSON mode:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a professional penetration tester and database integrator. Respond only in valid JSON."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        # [CHECKLIST] Extract and clean the model's response.
        json_output = response.choices[0].message.content.strip()
        
        # [CHECKLIST] Validate the JSON.
        structured_data = json.loads(json_output)
        return structured_data
    except Exception as e:
        logger.error(f"Failed to generate structured JSON output: {e}")
        # [CHECKLIST] Return an error dictionary in JSON mode for safety.
        return {"error": "Error generating structured JSON output."}

def insert_structured_data(data):
    """
    [✓] Inserts the structured JSON data into the PostgreSQL database.
         The data should have the following keys:
         "tests", "target_details", "vulnerabilities", "suggestions", "test_configurations", "reports".
    """
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS
        )
        conn.autocommit = True
        cur = conn.cursor()
        logger.info("🔗 Connected to PostgreSQL database for data insertion.")

        # Insert tests first because other tables may reference test_id
        for test in data.get("tests", []):
            insert_test_query = """
                INSERT INTO tests (test_id, user_id, test_name, test_date, test_status)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (test_id) DO NOTHING;
            """
            cur.execute(insert_test_query, (
                test["test_id"],
                test["user_id"],
                test["test_name"],
                test["test_date"],
                test["test_status"]
            ))
            logger.info(f"✅ Inserted test_id {test['test_id']} into tests.")

        # Insert target_details
        for target in data.get("target_details", []):
            insert_target_query = """
                INSERT INTO target_details (target_id, test_id, url_target, auth_email, auth_password, injection_fields)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (target_id) DO NOTHING;
            """
            # If auth_email, auth_password, and injection_fields are not provided, insert as NULL
            cur.execute(insert_target_query, (
                target["target_id"],
                target["test_id"],
                target["url_target"],
                target.get("auth_email"),
                target.get("auth_password"),
                json.dumps(target.get("injection_fields")) if target.get("injection_fields") else None
            ))
            logger.info(f"✅ Inserted target_id {target['target_id']} into target_details.")

        # Insert vulnerabilities
        for vuln in data.get("vulnerabilities", []):
            insert_vuln_query = """
                INSERT INTO vulnerabilities (vulnerability_id, test_id, vulnerability_name, endpoint, severity, cvss_score, potential_loss)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (vulnerability_id) DO NOTHING;
            """
            cur.execute(insert_vuln_query, (
                vuln["vulnerability_id"],
                vuln["test_id"],
                vuln["vulnerability_name"],
                vuln["endpoint"],
                vuln["severity"],
                vuln["cvss_score"],
                vuln["potential_loss"]
            ))
            logger.info(f"✅ Inserted vulnerability_id {vuln['vulnerability_id']} into vulnerabilities.")

        # Insert suggestions
        for sug in data.get("suggestions", []):
            insert_sug_query = """
                INSERT INTO suggestions (suggestion_id, vulnerability_id, suggestion_text, roi)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (suggestion_id) DO NOTHING;
            """
            cur.execute(insert_sug_query, (
                sug["suggestion_id"],
                sug["vulnerability_id"],
                sug["suggestion_text"],
                sug["roi"]
            ))
            logger.info(f"✅ Inserted suggestion_id {sug['suggestion_id']} into suggestions.")

        # Insert test_configurations
        for config in data.get("test_configurations", []):
            insert_config_query = """
                INSERT INTO test_configurations (config_id, test_id, config_name, config_date, status, options)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (config_id) DO NOTHING;
            """
            cur.execute(insert_config_query, (
                config["config_id"],
                config["test_id"],
                config["config_name"],
                config.get("config_date"),
                config["status"],
                json.dumps(config["options"]) if config.get("options") else None
            ))
            logger.info(f"✅ Inserted config_id {config['config_id']} into test_configurations.")

        # Insert reports
        for report in data.get("reports", []):
            insert_report_query = """
                INSERT INTO reports (report_id, test_id, vulnerability_count, compliance_score, framework_name, compliance_date, risk_score, summary, detailed_findings, report_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (report_id) DO NOTHING;
            """
            cur.execute(insert_report_query, (
                report["report_id"],
                report["test_id"],
                report["vulnerability_count"],
                report["compliance_score"],
                report["framework_name"],
                report["compliance_date"],
                report["risk_score"],
                report["summary"],
                report["detailed_findings"],
                report["report_date"]
            ))
            logger.info(f"✅ Inserted report_id {report['report_id']} into reports.")

        logger.info("🎉 All structured data inserted successfully into PostgreSQL!")
        cur.close()
        conn.close()
        logger.info("🔒 PostgreSQL connection closed.")
    except Exception as e:
        logger.error(f"Error inserting structured data into PostgreSQL: {e}")
        try:
            conn.rollback()
            conn.close()
        except:
            pass

if __name__ == "__main__":
    # Initialize OpenAI API key from environment variable (recommended)
    OPENAI_API_KEY = "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"
    if not OPENAI_API_KEY:
        logger.error("OPENAI_API_KEY is not set. Please set it as an environment variable.")
        sys.exit(1)

    try:
        launch_scan()
    except Exception as e:
        logger.critical(f"An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        print_context_buffers()
        # Generate structured JSON output based on context buffers
        structured_output = generate_executive_summary("o3-mini")
        print("\n=== Structured JSON Output ===")
        print(json.dumps(structured_output, indent=4))
        # Insert the structured JSON data into PostgreSQL
        insert_structured_data(structured_output)
