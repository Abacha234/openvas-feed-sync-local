# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.3744.1");
  script_cve_id("CVE-2024-21538", "CVE-2024-48948", "CVE-2024-48949", "CVE-2025-5889", "CVE-2025-6545", "CVE-2025-6547");
  script_tag(name:"creation_date", value:"2025-10-24 04:12:53 +0000 (Fri, 24 Oct 2025)");
  script_version("2025-10-27T05:40:39+0000");
  script_tag(name:"last_modification", value:"2025-10-27 05:40:39 +0000 (Mon, 27 Oct 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-09 19:15:25 +0000 (Mon, 09 Jun 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:3744-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:3744-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20253744-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245289");
  script_xref(name:"URL", value:"https://en.opensuse.org/openSUSE:Build_Service_prjconf#Substitute");
  script_xref(name:"URL", value:"https://github.com/boto/botocore/issues/3178");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-October/042269.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aws-cli, local-npm-registry, python-boto3, python-botocore, python-coverage, python-flaky, python-pluggy, python-pytest, python-pytest-cov, python-pytest-html, python-pytest-metadata, python-pytest-mock' package(s) announced via the SUSE-SU-2025:3744-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IVS does not support arns with the `svs` prefix
 * api-change:``ivs-realtime``: Bug Fix: IVS Real Time does not support ARNs using the `svs` prefix.
 * api-change:``rds``: Updates Amazon RDS documentation for setting local time zones for RDS for Db2
 DB instances.
 * api-change:``stepfunctions``: Add new ValidateStateMachineDefinition operation, which performs
 syntax checking on the definition of a Amazon States Language (ASL) state machine.
- from version 1.32.91
 * api-change:``datasync``: This change allows users to disable and enable the schedules associated
 with their tasks.
 * api-change:``ec2``: Launching capability for customers to enable or disable automatic assignment
 of public IPv4 addresses to their network interface
 * api-change:``emr-containers``: EMRonEKS Service support for SecurityConfiguration enforcement for
 Spark Jobs.
 * api-change:``entityresolution``: Support Batch Unique IDs Deletion.
 * api-change:``gamelift``: Amazon GameLift releases container fleets support for public preview.
 Deploy Linux-based containerized game server software for hosting on Amazon GameLift.
 * api-change:``ssm``: Add SSM DescribeInstanceProperties API to public AWS SDK.
- from version 1.32.90
 * api-change:``bedrock``: This release introduces Model Evaluation and Guardrails for Amazon
 Bedrock.
 * api-change:``bedrock-agent``: Introducing the ability to create multiple data sources per
 knowledge base, specify S3 buckets as data sources from external accounts, and exposing levers to
 define the deletion behavior of the underlying vector store data.
 * api-change:``bedrock-agent-runtime``: This release introduces zero-setup file upload support for
 the RetrieveAndGenerate API. This allows you to chat with your data without setting up a Knowledge
 Base.
 * api-change:``bedrock-runtime``: This release introduces Guardrails for Amazon Bedrock.
 * api-change:``ce``: Added additional metadata that might be applicable to your reservation
 recommendations.
 * api-change:``ec2``: This release introduces EC2 AMI Deregistration Protection, a new AMI property
 that can be enabled by customers to protect an AMI against an unintended deregistration. This
 release also enables the AMI owners to view the AMI 'LastLaunchedTime' in DescribeImages API.
 * api-change:``pi``: Clarifies how aggregation works for GetResourceMetrics in the Performance
 Insights API.
 * api-change:``rds``: Fix the example ARN for ModifyActivityStreamRequest
 * api-change:``workspaces-web``: Added InstanceType and MaxConcurrentSessions parameters on
 CreatePortal and UpdatePortal Operations as well as the ability to read Customer Managed Key &
 Additional Encryption Context parameters on supported resources (Portal, BrowserSettings,
 UserSettings, IPAccessSettings)
- from version 1.32.89
 * api-change:``bedrock-agent``: Releasing the support for simplified configuration and return of
 control
 * ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'aws-cli, local-npm-registry, python-boto3, python-botocore, python-coverage, python-flaky, python-pluggy, python-pytest, python-pytest-cov, python-pytest-html, python-pytest-metadata, python-pytest-mock' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"python311-coverage", rpm:"python311-coverage~7.6.10~150400.12.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pluggy", rpm:"python311-pluggy~1.5.0~150400.14.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pytest", rpm:"python311-pytest~8.3.5~150400.3.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pytest-cov", rpm:"python311-pytest-cov~6.2.1~150400.12.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pytest-mock", rpm:"python311-pytest-mock~3.14.0~150400.13.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"python311-coverage", rpm:"python311-coverage~7.6.10~150400.12.6.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pluggy", rpm:"python311-pluggy~1.5.0~150400.14.10.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pytest", rpm:"python311-pytest~8.3.5~150400.3.9.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pytest-cov", rpm:"python311-pytest-cov~6.2.1~150400.12.6.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pytest-mock", rpm:"python311-pytest-mock~3.14.0~150400.13.6.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
