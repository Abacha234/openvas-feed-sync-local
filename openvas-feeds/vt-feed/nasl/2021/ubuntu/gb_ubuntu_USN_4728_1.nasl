# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844823");
  script_cve_id("CVE-2020-27352");
  script_tag(name:"creation_date", value:"2021-02-10 04:01:26 +0000 (Wed, 10 Feb 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4728-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4728-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4728-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'snapd' package(s) announced via the USN-4728-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gilad Reti and Nimrod Stoler discovered that snapd did not correctly specify cgroup
delegation when generating systemd service units for various container
management snaps. This could allow a local attacker to escalate privileges
via access to arbitrary devices of the container host from within a
compromised or malicious container.");

  script_tag(name:"affected", value:"'snapd' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
