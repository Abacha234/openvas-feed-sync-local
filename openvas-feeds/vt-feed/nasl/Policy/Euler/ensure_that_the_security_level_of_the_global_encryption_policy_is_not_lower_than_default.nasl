# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# ------------------------------------------------------------------
# METADATA
# ------------------------------------------------------------------

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130388");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the Security Level of the Global Encryption Policy Is Not Lower than DEFAULT");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: openEuler Security Configuration Baseline (v1.0.0): 2. Secure Access: 2.6 Data Security: 2.6.2 Ensure That the Security Level of the Global Encryption Policy Is Not Lower than DEFAULT (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: openEuler Security Configuration Baseline (v1.0.0): 2. Secure Access: 2.6 Data Security: 2.6.2 Ensure That the Security Level of the Global Encryption Policy Is Not Lower than DEFAULT (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): openEuler Security Configuration Baseline (v1.0.0): 2. Secure Access: 2.6 Data Security: 2.6.2 Ensure That the Security Level of the Global Encryption Policy Is Not Lower than DEFAULT (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: openEuler Security Configuration Baseline (v1.0.0): 2. Secure Access: 2.6 Data Security: 2.6.2 Ensure That the Security Level of the Global Encryption Policy Is Not Lower than DEFAULT (Recommendation)");

  script_tag(name:"summary", value:"The global encryption/decryption policy of the system is used
to specify the algorithms supported by the encryption and decryption components. You can change the
preset security policy level by modifying the /etc/crypto-policies/config configuration file to
change the algorithm set that can be used by applications.

openEuler is configured with the DEFAULT policy by default. The policy level can be LEGACY,
DEFAULT, NEXT, FUTURE, or FIPS. You are advised to set the policy level to a value higher than or
equal to DEFAULT. That is, the LEGACY mode cannot be set.

LEGACY: The policy delivers the maximum compatibility with the old system, but it is not secure.
This policy provides a security level of at least 64 bits. DEFAULT: It is the default policy that
complies with the current standard. This policy provides a security level of at least 80 bits.
NEXT: It is a policy prepared for the OS to be released. This policy provides a security level of
at least 112 bits (Note: SHA-1 signatures required by DNSSEC and other SHA-1 signatures in common
use are excluded). FUTURE: It is a policy with a higher security level and can defend against most
recent attacks. This policy provides a security level of at least 128 bits. FIPS: It is a policy
complying with FIPS 140-2 requirements. This policy provides a security level of at least 112 bits.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That the Security Level of the Global Encryption Policy Is Not Lower than DEFAULT";

solution = "Configure a proper policy in the /etc/crypto-policies/config file:

# vim /etc/crypto-policies/config
DEFAULT";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -vE "^\\s*#" /etc/crypto-policies/config | grep LEGACY';

expected_value = 'The output should be empty';

# ------------------------------------------------------------------
# CONNECTION CHECK
# ------------------------------------------------------------------

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){

  report_ssh_error(title: title,
                   solution: solution,
                   action: action,
                   expected_value: expected_value,
                   check_type: check_type);
  exit(0);
}

# ------------------------------------------------------------------
# CHECK : Verify command `grep -vE "^\s*#" /etc/crypto-policies/config | grep LEGACY`
# ------------------------------------------------------------------

step_cmd = 'grep -vE "^\\s*#" /etc/crypto-policies/config | grep LEGACY';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(eregmatch(string: actual_value, pattern:"(No such file or directory|Permission denied|Command not found|Segmentation fault|service not found|is not running|syntax error near unexpected token|syntax error: unexpected end of file)", icase: TRUE)){
  compliant = "incomplete";
  comment = "Something went wrong during the audit check. Please try again.";
}else if(!actual_value){
  compliant = "yes";
  comment = "Check passed";
}else{
  compliant = "no";
  comment = "Check failed";
}

# ------------------------------------------------------------------
# REPORT
# ------------------------------------------------------------------

target = get_kb_item("ssh/login/release_notus");
comment = "Target: " + target + "\n" + comment;

report_audit(action: action,
             actual_value: actual_value,
             expected_value: expected_value,
             is_compliant: compliant,
             solution: solution,
             check_type: check_type,
             title: title,
             comment: comment);

exit(0);
