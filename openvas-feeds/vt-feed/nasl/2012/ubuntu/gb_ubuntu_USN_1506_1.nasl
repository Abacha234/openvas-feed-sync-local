# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841079");
  script_cve_id("CVE-2012-3864", "CVE-2012-3865", "CVE-2012-3866", "CVE-2012-3867");
  script_tag(name:"creation_date", value:"2012-07-16 06:23:14 +0000 (Mon, 16 Jul 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1506-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1506-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1506-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'puppet' package(s) announced via the USN-1506-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Puppet incorrectly handled certain HTTP GET
requests. An attacker could use this flaw with a valid client certificate
to retrieve arbitrary files from the Puppet primary server.
(CVE-2012-3864)

It was discovered that Puppet incorrectly handled Delete requests. If a
Puppet primary server were reconfigured to allow the 'Delete' method, an
attacker on an authenticated host could use this flaw to delete arbitrary
files from the Puppet server, leading to a denial of service.
(CVE-2012-3865)

It was discovered that Puppet incorrectly set file permissions on the
last_run_report.yaml file. An attacker could use this flaw to access
sensitive information. This issue only affected Ubuntu 11.10 and Ubuntu
12.04 LTS. (CVE-2012-3866)

It was discovered that Puppet incorrectly handled agent certificate names.
An attacker could use this flaw to create a specially crafted certificate
and trick an administrator into signing a certificate that can then be used
to machine-in-the-middle agent nodes. (CVE-2012-3867)");

  script_tag(name:"affected", value:"'puppet' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
