# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Module name: Policy Reporting.
# Description: Provides to custom and generic reporting audit results.

# ----------------------------------------------------------------------
# Constant messages / keywords
# ----------------------------------------------------------------------

KEY_NOT_FOUND_MESSAGE = "The setting was not found on the target.";
USER_RIGHT_ASSIGNMENT_ENGINE_PRIVILEGE_ERROR_MESSAGE =
  "Cannot query RSOP_UserPrivilegeRight on the host";
WINDOWS_PASSWORD_POLICY_ENGINE_PRIVILEGE_ERROR_MESSAGE =
  "Cannot query RSOP_SecuritySettingNumeric or RSOP_SecuritySettingBoolean on the host";
WMI_ENGINE_CONNECTION_ERROR_MESSAGE =
  "Missing connection information to log in into the host";
WRONG_OPERATING_SYSTEM_ERROR_MESSAGE = "Host does not run";
NON_COMPLETED_KEYWORD = "incomplete";
NON_COMPLIANT_KEYWORD = "no";
NOT_FOUND_KEYWORD = "None";
ERROR_KEYWORD = "Error";
SSH_ERROR = "No SSH connection to host";

# ----------------------------------------------------------------------
# Convenience wrappers for frequently occurring error conditions
# ----------------------------------------------------------------------

# @brief  Report registry key / setting not found.
# @param  title            Policy control title.
# @param  solution         How to remediate.
# @param  action           Test step action (command, description etc).
# @param  expected_value   Compliance set-point.
# @param  check_type       Check type (RegKey, SSH_Cmd, etc).
function report_ssh_error(title, solution, action, expected_value, check_type) {

    local_var title, solution, action, expected_value, check_type;

    report_audit(
        actual_value: NOT_FOUND_KEYWORD,
        action: action,
        expected_value: expected_value,
        is_compliant: NON_COMPLIANT_KEYWORD,
        solution: solution,
        check_type: check_type,
        title: title,
        comment: SSH_ERROR + " " + action
    );
}

# @brief  Report registry key / setting not found.
# @param  title            Policy control title.
# @param  solution         How to remediate.
# @param  action           Test step action (command, description etc).
# @param  expected_value   Compliance set-point.
# @param  check_type       Check type (RegKey, SSH_Cmd, etc).
function report_key_not_found_error(title, solution, action, expected_value, check_type) {

    local_var title, solution, action, expected_value, check_type;

    report_audit(
        actual_value: NOT_FOUND_KEYWORD,
        action: action,
        expected_value: expected_value,
        is_compliant: NON_COMPLIANT_KEYWORD,
        solution: solution,
        check_type: check_type,
        title: title,
        comment: KEY_NOT_FOUND_MESSAGE + " " + action
        );
}

# @brief  Report wrong operating system (VT executed on an unsupported host).
# @param  title            Policy control title.
# @param  solution         How to remediate.
# @param  action           Test step action (command, description etc).
# @param  expected_value   Compliance set-point.
# @param  check_type       Check type (RegKey, SSH_Cmd, etc).
# @param  target_os        Required OS string (e.g. Windows Server 2019).
function report_wrong_operation_system_error(
           title, solution, action, expected_value, check_type, target_os){

    local_var title, solution, action, expected_value, check_type, target_os;

    report_audit(
        action : action,
        actual_value : NOT_FOUND_KEYWORD,
        expected_value : expected_value,
        is_compliant : NON_COMPLETED_KEYWORD,
        solution : solution,
        check_type : check_type,
        title : title,
        comment : WRONG_OPERATING_SYSTEM_ERROR_MESSAGE + target_os + "."
    );
}

# @brief  Report password-policy querying error on Windows hosts.
function report_windows_password_policy_querying_error(
           title, solution, action, expected_value, check_type){

    local_var title, solution, action, expected_value, check_type;

    report_audit(
        action : action,
        actual_value : ERROR_KEYWORD,
        expected_value : expected_value,
        is_compliant : NON_COMPLETED_KEYWORD,
        solution : solution,
        check_type : check_type,
        title : title,
        comment : WINDOWS_PASSWORD_POLICY_ENGINE_PRIVILEGE_ERROR_MESSAGE
    );
}

# @brief  Report WMI connection error.
function report_wmi_connection_error(
           title, solution, action, expected_value, check_type){

    local_var title, solution, action, expected_value, check_type;

    report_audit(
        action : action,
        actual_value : ERROR_KEYWORD,
        expected_value : expected_value,
        is_compliant : NON_COMPLETED_KEYWORD,
        solution : solution,
        check_type : check_type,
        title : title,
        comment : WMI_ENGINE_CONNECTION_ERROR_MESSAGE
    );
}

# @brief  Report privilege error when enumerating Windows user-right assignments.
function report_user_right_assignment_privilege_error(
           title, solution, action, expected_value, check_type){

    local_var title, solution, action, expected_value, check_type;

    report_audit(
        action : action,
        actual_value : ERROR_KEYWORD,
        expected_value : expected_value,
        is_compliant : NON_COMPLETED_KEYWORD,
        solution : solution,
        check_type : check_type,
        title : title,
        comment : USER_RIGHT_ASSIGNMENT_ENGINE_PRIVILEGE_ERROR_MESSAGE
    );
}

# ----------------------------------------------------------------------
# Core helpers
# ----------------------------------------------------------------------

# @brief  Central entry: build report *and* fill all KB keys.
# @param  action           Test step action (command, description etc).
# @param  actual_value     Result observed on the target.
# @param  expected_value   Compliance set-point.
# @param  is_compliant     yes / no / incomplete / error.
# @param  solution         How to remediate.
# @param  check_type       Check type (RegKey, SSH_Cmd, etc).
# @param  title            Policy control title.
# @param  comment          Optional extra info for the report.
function report_audit(action, actual_value, expected_value, is_compliant,
                      solution, check_type, title, comment){

    local_var actual_value, action, expected_value, is_compliant,
            solution, check_type, title, comment;

    audit_reporting(
        action : action,
        actual_value : actual_value,
        expected_value : expected_value,
        is_compliant : is_compliant,
        solution : solution,
        check_type : check_type,
        comment : comment
    );

    audit_set_kbs(
        action : action,
        check_type : check_type,
        expected_value : expected_value,
        solution : solution,
        title : title,
        actual_value : actual_value,
        is_compliant : is_compliant,
        comment : comment
    );
}

# @brief  Persist all per-VT KB keys required by Greenbone Compliance Reports.
function audit_set_kbs(action, check_type, expected_value, solution,
                       title, actual_value, is_compliant, comment){

    local_var action, check_type, expected_value, solution, title, actual_value, is_compliant;

    if(!check_type){
        check_type = "None";
    }

    if(!action){
        action = "None";
    }

    if(!expected_value){
        expected_value = "None";
    }

    if(!solution){
        solution = "None";
    }

    if(!title){
        title = "None";
    }

    if(!is_compliant){
        is_compliant = "None";
    }

    if(!comment){
        comment = "None";
    }

    title = str_replace(string:title, find:'\n', replace:' ');
    set_kb_item(name:get_script_oid() + "/TEST_TYPE", value:check_type);
    set_kb_item(name:get_script_oid() + "/NAME", value:title);
    set_kb_item(name: get_script_oid() + "/FIX", value:solution);
    set_kb_item(name:get_script_oid() + "/CMD", value:chomp(string(action)));
    set_kb_item(name:get_script_oid() + "/DEFAULT", value:chomp(string(expected_value)));
    set_kb_item(name:get_script_oid() + "/RESULT", value:chomp(string(actual_value)));
    set_kb_item(name:get_script_oid() + "/COMPLIANT", value:string(is_compliant));
    set_kb_item(name:get_script_oid() + "/NOTE", value:comment);
    set_kb_item(name:"PolicyOIDs", value:get_script_oid());
}

# @brief  Build a single compliance report line **and** write vt_debug_empty
#         keys whenever mandatory fields are missing / empty.
function audit_reporting(action, actual_value, expected_value, is_compliant,
                         solution, check_type, comment){

    local_var action, actual_value, expected_value, is_compliant,
            solution, check_type, comment, report;

    if(!action){
        action = "";
        set_kb_item(name: "vt_debug_empty/" + get_script_oid(),
        value: get_script_oid() + "#-#policy_reporting#-#test");
    }

    if(!actual_value){
        actual_value = "";
        set_kb_item(name: "vt_debug_empty/" + get_script_oid(),
        value: get_script_oid() + "#-#policy_reporting#-#result");
    }

    if(!expected_value){
        expected_value = "";
        set_kb_item(name: "vt_debug_empty/" + get_script_oid(),
        value: get_script_oid() + "#-#policy_reporting#-#default");
    }

    if(!is_compliant){
        is_compliant = "";
        set_kb_item(name: "vt_debug_empty/" + get_script_oid(),
                    value: get_script_oid() + "#-#policy_reporting#-#compliant");
        is_compliant = "Incomplete";
    }

    if(!solution){
        solution = "";
        set_kb_item(name: "vt_debug_empty/" + get_script_oid(),
        value: get_script_oid() + "#-#policy_reporting#-#fixtext");
    }

    if(!check_type){
        check_type = "";
        set_kb_item(name: "vt_debug_empty/" + get_script_oid(),
        value: get_script_oid() + "#-#policy_reporting#-#type");
    }

    report  = "Compliant:    " + toupper(is_compliant) + '\n';
    report += "Actual Value: " + actual_value + '\n';
    report += "Set Point:    " + expected_value + '\n';
    report += "Type of Test: " + check_type + '\n';
    report += "Test:         " + action + '\n';
    report += "Solution:     " + solution;

    if(comment){
        report += '\n' + "Notes:        " + comment;
    }

    audit_logging(text:report);
}

# ----------------------------------------------------------------------
# Formatting / logging helpers
# ----------------------------------------------------------------------

# @brief  Send the report to the NASL log stream
#         (only if Compliance/verbose is set).
function audit_logging(text, error){

    local_var text, error, verbose;

    verbose = get_kb_item("Compliance/verbose");

    if(verbose){
        if(error){
            log_message(data: text, port: 0, proto: "Policy/Control/Error");
        }else{
            log_message(data: text, port: 0, proto: "Policy/Control");
        }
    }
}
