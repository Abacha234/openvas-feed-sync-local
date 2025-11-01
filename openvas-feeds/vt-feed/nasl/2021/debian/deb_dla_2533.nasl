# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892533");
  script_cve_id("CVE-2020-35459");
  script_tag(name:"creation_date", value:"2021-01-26 04:00:05 +0000 (Tue, 26 Jan 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-02 15:00:00 +0000 (Tue, 02 Feb 2021)");

  script_name("Debian: Security Advisory (DLA-2533)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2533");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2533");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'crmsh' package(s) announced via the DLA-2533 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an in issue in the command-line tool for the Pacemaker High Availability stack. Local attackers were able to execute commands via shell code injection to the crm history command-line tool, potentially allowing escalation of privileges.

CVE-2020-35459

An issue was discovered in ClusterLabs crmsh through 4.2.1. Local attackers able to call 'crm history' (when 'crm' is run) were able to execute commands via shell code injection to the crm history commandline, potentially allowing escalation of privileges.

For Debian 9 Stretch, these problems have been fixed in version 2.3.2-4+deb9u1.

We recommend that you upgrade your crmsh packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'crmsh' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);