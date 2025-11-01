# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841001");
  script_cve_id("CVE-2011-4086", "CVE-2012-1090", "CVE-2012-2100", "CVE-2012-4398");
  script_tag(name:"creation_date", value:"2012-05-08 07:07:31 +0000 (Tue, 08 May 2012)");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 23:02:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-1432-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1432-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1432-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1432-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Linux's kernels ext4 file system when mounted with
a journal. A local, unprivileged user could exploit this flaw to cause a
denial of service. (CVE-2011-4086)

A flaw was discovered in the Linux kernel's cifs file system. An
unprivileged local user could exploit this flaw to crash the system leading
to a denial of service. (CVE-2012-1090)

A flaw was found in the Linux kernel's ext4 file system when mounting a
corrupt filesystem. A user-assisted remote attacker could exploit this flaw
to cause a denial of service. (CVE-2012-2100)

Tetsuo Handa reported a flaw in the OOM (out of memory) killer of the Linux
kernel. A local unprivileged user can exploit this flaw to cause system
instability and denial of services. (CVE-2012-4398)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
