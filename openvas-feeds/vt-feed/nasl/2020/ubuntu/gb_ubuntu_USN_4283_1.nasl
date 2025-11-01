# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844348");
  script_cve_id("CVE-2020-1711", "CVE-2020-7039", "CVE-2020-8608");
  script_tag(name:"creation_date", value:"2020-02-19 04:01:33 +0000 (Wed, 19 Feb 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-14 03:50:00 +0000 (Sun, 14 Feb 2021)");

  script_name("Ubuntu: Security Advisory (USN-4283-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4283-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4283-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-4283-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Felipe Franciosi, Raphael Norwitz, and Peter Turschmid discovered that QEMU
incorrectly handled iSCSI server responses. A remote attacker in control of
the iSCSI server could use this issue to cause QEMU to crash, leading to a
denial of service, or possibly execute arbitrary code. (CVE-2020-1711)

It was discovered that the QEMU libslirp component incorrectly handled
memory. A remote attacker could use this issue to cause QEMU to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2020-7039, CVE-2020-8608)");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
