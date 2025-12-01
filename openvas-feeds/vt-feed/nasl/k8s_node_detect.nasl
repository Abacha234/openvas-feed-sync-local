# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.137000");
  script_version("2025-11-21T15:39:49+0000");
  script_tag(name:"last_modification", value:"2025-11-21 15:39:49 +0000 (Fri, 21 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-17 09:57:04 +0000 (Mon, 17 Nov 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");

  script_name("Kubernetes: Node Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Compliance");
  script_dependencies("kubernetes_config.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_tag(name:"summary", value:"Detection of the Kubernetes node type");

  exit(0);
}

include("ssh_func.inc");

api_server = get_kb_item("Policy/kubernetes/manifests/api_server");
controller_manager = get_kb_item("Policy/kubernetes/manifests/controller_manager");
scheduler = get_kb_item("Policy/kubernetes/manifests/scheduler");
etcd = get_kb_item("Policy/kubernetes/manifests/etcd");
config = get_kb_item("Policy/kubernetes/kubelet/config");
config2 = get_kb_item("Policy/kubernetes/kubelet/config2");

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  exit(0);
}

cmd_controller_file_api_server = 'ls ' + api_server + ' 2>/dev/null';
value_controller_file_api_server = ssh_cmd(socket:sock, cmd:cmd_controller_file_api_server, return_errors:TRUE, return_linux_errors_only:TRUE);
cmd_controller_file_controller_manager = 'ls ' + controller_manager + ' 2>/dev/null';
value_controller_file_controller_manager = ssh_cmd(socket:sock, cmd:cmd_controller_file_controller_manager, return_errors:TRUE, return_linux_errors_only:TRUE);
cmd_controller_file_scheduler = 'ls ' + scheduler + ' 2>/dev/null';
value_controller_file_scheduler = ssh_cmd(socket:sock, cmd:cmd_controller_file_scheduler, return_errors:TRUE, return_linux_errors_only:TRUE);
cmd_controller_file_etcd = 'ls ' + etcd + ' 2>/dev/null';
value_controller_file_etcd = ssh_cmd(socket:sock, cmd:cmd_controller_file_etcd, return_errors:TRUE, return_linux_errors_only:TRUE);
cmd_controller_processes = 'ps aux | grep -E "[k]ube-apiserver|[k]ube-controller-manager|[k]ube-scheduler" 2>/dev/null';
value_controller_processes = ssh_cmd(socket:sock, cmd:cmd_controller_processes, return_errors:TRUE, return_linux_errors_only:TRUE);

if(value_controller_file_api_server
 || value_controller_file_controller_manager
 || value_controller_file_scheduler
 || strstr(value_controller_processes, "kube-apiserver")
 || strstr(value_controller_processes, "kube-controller-manager")
 || strstr(value_controller_processes, "kube-scheduler")) {
  set_kb_item(name:"Policy/kubernetes/is_controller", value:TRUE);
}

if(value_controller_file_etcd) {
  set_kb_item(name:"Policy/kubernetes/is_etcd", value:TRUE);
}

cmd_worker_file_config = 'ls ' + config + ' 2>/dev/null';
value_worker_file_config = ssh_cmd(socket:sock, cmd:cmd_worker_file_config, return_errors:TRUE, return_linux_errors_only:TRUE);
cmd_worker_file_config2 = 'ls ' + config2 + ' 2>/dev/null';
value_worker_file_config2 = ssh_cmd(socket:sock, cmd:cmd_worker_file_config2, return_errors:TRUE, return_linux_errors_only:TRUE);
cmd_worker_process = 'ps aux | grep "[k]ubelet" 2>/dev/null';
value_worker_process = ssh_cmd(socket:sock, cmd:cmd_worker_process, return_errors:TRUE, return_linux_errors_only:TRUE);

if(value_worker_file_config || value_worker_file_config2 || value_worker_process) {
  set_kb_item(name:"Policy/kubernetes/is_worker", value:TRUE);
}
exit(0);