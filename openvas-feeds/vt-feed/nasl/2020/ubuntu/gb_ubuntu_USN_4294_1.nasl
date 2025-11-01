# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844356");
  script_cve_id("CVE-2020-8793", "CVE-2020-8794");
  script_tag(name:"creation_date", value:"2020-03-03 04:01:05 +0000 (Tue, 03 Mar 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-04 18:15:00 +0000 (Tue, 04 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-4294-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4294-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4294-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensmtpd' package(s) announced via the USN-4294-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenSMTPD mishandled certain input. A remote,
unauthenticated attacker could use this vulnerability to execute arbitrary
shell commands as any non-root user. (CVE-2020-8794)

It was discovered that OpenSMTPD did not properly handle hardlinks under
certain conditions. An unprivileged local attacker could read the first
line of any file on the filesystem. (CVE-2020-8793)");

  script_tag(name:"affected", value:"'opensmtpd' package(s) on Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
