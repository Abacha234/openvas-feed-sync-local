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
  script_oid("1.3.6.1.4.1.25623.1.0.130367");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure a Proper Default Zone");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/euleros_openeuler");

  script_add_preference(name:"Firewalld service default zone", type:"entry", value:"Server;Workstation;block;dmz;drop;external;home;internal;public;trusted;work", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.2 Configure a Proper Default Zone (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.2 Configure a Proper Default Zone (Recommendation)");

  script_tag(name:"summary", value:"The firewalld service allows several independent rule zones to
be created on a firewall based on the zone concept. Different interfaces or source addresses can be
bound to different zones to implement different control logic. A zone can be configured with many
different network interfaces or source addresses. However, an interface or source address can be
bound to only one zone. This can determine the rules to be implemented when packets enter or leave
the zone.

If no explicit rule is matched when a zone processes packets from an interface or source address,
the zone can determine how to process the packets, for example, accept or reject the packets, or
directly send the packets to the default zone for processing.

You should configure a proper default zone based on the actual service scenario. All network
resources, such as interfaces, source addresses, and connections, that are not explicitly allocated
to a specified zone must be allocated to the default zone.

If the default zone is not properly configured, unexpected impacts may occur on network resources
that are not bound to other zones.

If all network resources have been explicitly bound to other zones for which detailed rules have
been formulated, and no rule is configured for the default zone, the default zone does not affect
the services. But this is not recommended.

The openEuler firewalld service provides 11 zone types: Server, Workstation, block, dmz, drop,
external, home, internal, public, trusted, and work. The default zone is public.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

firewalld_service_default_zone = script_get_preference("Firewalld service default zone");

title = "Configure a Proper Default Zone";

solution = "Run the firewall-cmd command to configure the default zone.

# firewall-cmd --set-default-zone=";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# firewall-cmd --get-default-zone';

expected_value = 'The output should be equal to "'+firewalld_service_default_zone+'"';

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
# CHECK : Check default zones
# ------------------------------------------------------------------

step_cmd = 'firewall-cmd --get-default-zone';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(eregmatch(string: actual_value, pattern:"(No such file or directory|Permission denied|Command not found|Segmentation fault|service not found|is not running|syntax error near unexpected token|syntax error: unexpected end of file)", icase: TRUE)){
  compliant = "incomplete";
  comment = "Something went wrong during the audit check. Please try again.";
}else if(actual_value == ''+firewalld_service_default_zone+''){
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
